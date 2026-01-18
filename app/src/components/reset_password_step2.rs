use crate::{
    components::{
        form::{field::Field, submit::Submit},
            router::{AppRoute, Link},
    },
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
        obfuscate::obfuscate_password,
    },
};
use anyhow::{Result, bail};
use lldap_auth::{
    opaque::client::registration as opaque_registration,
    password_reset::ServerPasswordResetResponse, registration,
};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};
use graphql_client::GraphQLQuery;

/// The fields of the form, with the constraints.
#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct FormModel {
    #[validate(length(min = 8, message = "Invalid password. Min length: 8"))]
    password: String,
    #[validate(must_match(other = "password", message = "Passwords must match"))]
    confirm_password: String,
}

#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "src/queries/get_kerberos_info.graphql",
response_derives = "Debug,Clone,PartialEq,Eq",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetKerberosInfo;

#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "src/queries/sync_kerberos.graphql",
response_derives = "Debug,Clone",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct SyncKerberosPassword;

pub struct ResetPasswordStep2Form {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
        username: Option<String>,
        opaque_data: Option<opaque_registration::ClientRegistration>,
        kerberos_info: Option<get_kerberos_info::GetKerberosInfoKerberosInfo>,
        fetched_kerberos: bool,
        obfuscated_password: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Properties)]
pub struct Props {
    pub token: String,
}

pub enum Msg {
    ValidateTokenResponse(Result<ServerPasswordResetResponse>),
    KerberosInfoResponse(Result<get_kerberos_info::ResponseData>),
    FormUpdate,
    Submit,
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStartResponse>>),
    RegistrationFinishResponse(Result<()>),
    SyncKerberosResponse(Result<sync_kerberos_password::ResponseData>),
}

impl CommonComponent<ResetPasswordStep2Form> for ResetPasswordStep2Form {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        use anyhow::Context;
        match msg {
            Msg::ValidateTokenResponse(response) => {
                self.username = Some(response?.user_id);
                Ok(true)
            }
            Msg::KerberosInfoResponse(res) => {
                self.kerberos_info = Some(res?.kerberos_info);
                Ok(true)
            }
            Msg::FormUpdate => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let mut rng = rand::rngs::OsRng;
                let new_password = self.form.model().password;
                let registration_start_request =
                opaque_registration::start_registration(new_password.as_bytes(), &mut rng)
                .context("Could not initiate password change")?;
                let req = registration::ClientRegistrationStartRequest {
                    username: self.username.as_ref().unwrap().clone().into(),
                    registration_start_request: registration_start_request.message,
                };
                self.opaque_data = Some(registration_start_request.state);
                self.common.call_backend(
                    ctx,
                    HostService::register_start(req),
                                         Msg::RegistrationStartResponse,
                );
                if let Some(kerberos_info) = &self.kerberos_info {
                    if kerberos_info.enabled {
                        if let Some(key) = &kerberos_info.encode_key {
                            self.obfuscated_password = Some(obfuscate_password(
                                &new_password,
                                key,
                            ));
                        }
                    }
                }
                Ok(true)
            }
            Msg::RegistrationStartResponse(res) => {
                let res = res.context("Could not initiate password change")?;
                let registration = self.opaque_data.take().expect("Missing registration data");
                let mut rng = rand::rngs::OsRng;
                let registration_finish = opaque_registration::finish_registration(
                    registration,
                    res.registration_response,
                    &mut rng,
                )
                .context("Error during password change")?;
                let req = registration::ClientRegistrationFinishRequest {
                    server_data: res.server_data,
                    registration_upload: registration_finish.message,
                };
                self.common.call_backend(
                    ctx,
                    HostService::register_finish(req),
                                         Msg::RegistrationFinishResponse,
                );
                Ok(true)
            }
            Msg::RegistrationFinishResponse(response) => {
                if response.is_ok() {
                    if self.obfuscated_password.is_some() {
                        let variables = sync_kerberos_password::Variables {
                            user_id: self.username.clone().unwrap(),
                            obfuscated_password: self.obfuscated_password.clone().unwrap(),
                        };
                        self.common.call_graphql::<SyncKerberosPassword, _>(
                            ctx,
                            variables,
                            Msg::SyncKerberosResponse,
                            "Error trying to sync Kerberos password",
                        );
                        Ok(false)
                    } else {
                        ctx.link().history().unwrap().push(AppRoute::Login);
                        Ok(true)
                    }
                } else {
                    response?;
                    Ok(true)
                }
            }
            Msg::SyncKerberosResponse(response) => {
                response?;
                ctx.link().history().unwrap().push(AppRoute::Login);
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for ResetPasswordStep2Form {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut component = ResetPasswordStep2Form {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::<FormModel>::new(FormModel::default()),
                opaque_data: None,
                username: None,
                kerberos_info: None,
                fetched_kerberos: false,
                obfuscated_password: None,
        };
        let token = ctx.props().token.clone();
        component.common.call_backend(
            ctx,
            HostService::reset_password_step2(token),
                                      Msg::ValidateTokenResponse,
        );
        component
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        match (&self.username, &self.common.error) {
            (None, None) => {
                return html! {
                    {"Validating token"}
                };
            }
            (None, Some(e)) => {
                return html! {
                    <>
                    <div class="alert alert-danger">
                    {e.to_string() }
                    </div>
                    <Link
                    classes="btn-link btn"
                    disabled={self.common.is_task_running()}
                    to={AppRoute::Login}>
                    {"Back"}
                    </Link>
                    </>
                };
            }
            _ => (),
        };
        if self.kerberos_info.is_none() {
            return html! {
                <div>{"Loading Kerberos info..."}</div>
            };
        }
        html! {
            <>
            <h2>{"Reset your password"}</h2>
            <form class="form">
            <Field<FormModel>
            label="New password"
            required=true
            form={&self.form}
            field_name="password"
            autocomplete="new-password"
            input_type="password"
            oninput={link.callback(|_| Msg::FormUpdate)} />
            <Field<FormModel>
            label="Confirm password"
            required=true
            form={&self.form}
            field_name="confirm_password"
            autocomplete="new-password"
            input_type="password"
            oninput={link.callback(|_| Msg::FormUpdate)} />
            <Submit
            disabled={self.common.is_task_running()}
            onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})} />
            </form>
            { if let Some(e) = &self.common.error {
                html! {
                    <div class="alert alert-danger">
                    {e.to_string() }
                    </div>
                }
            } else { html! {} }
            }
            </>
        }
    }
    fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
        if first_render && !self.fetched_kerberos {
            gloo_console::log!("Rendered: fetching Kerberos info");
            self.common.call_graphql::<GetKerberosInfo, _>(
                ctx,
                get_kerberos_info::Variables {},
                Msg::KerberosInfoResponse,
                "Error fetching Kerberos info",
            );
            self.fetched_kerberos = true;
        }
    }
}
