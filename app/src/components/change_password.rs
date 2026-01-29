use crate::{
    components::{
        form::{field::Field, submit::Submit},
            router::{AppRoute, Link},
    },
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
        encrypt::encrypt_password,
    },
};
use anyhow::{Result, bail};
use gloo_console::log as console_log;
use graphql_client::GraphQLQuery;
use lldap_auth::*;
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};
use gloo_console::log;

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

#[derive(PartialEq, Eq, Default)]
enum OpaqueData {
    #[default]
    None,
    Login(opaque::client::login::ClientLogin),
    Registration(opaque::client::registration::ClientRegistration),
}

impl OpaqueData {
    fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

/// The fields of the form, with the constraints.
#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct FormModel {
    #[validate(custom(
    function = "empty_or_long",
    message = "Password should be longer than 8 characters"
    ))]
    old_password: String,
    #[validate(length(min = 8, message = "Invalid password. Min length: 8"))]
    password: String,
    #[validate(must_match(other = "password", message = "Passwords must match"))]
    confirm_password: String,
}

fn empty_or_long(value: &str) -> Result<(), validator::ValidationError> {
    if value.is_empty() || value.len() >= 8 {
        Ok(())
    } else {
        Err(validator::ValidationError::new(""))
    }
}

pub struct ChangePasswordForm {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
        opaque_data: OpaqueData,
        kerberos_info: Option<get_kerberos_info::GetKerberosInfoKerberosInfo>,
        fetched_kerberos: bool,
        encrypted_password: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Properties)]
pub struct Props {
    pub username: String,
    pub is_admin: bool,
}

pub enum Msg {
    FormUpdate,
    Submit,
    LoginStartResponse(Result<Box<login::ServerLoginStartResponse>>),
    LoginFinishResponse(Result<(String, bool)>),
    SubmitNewPassword,  // NEW: Transition msg after old pw verify
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStartResponse>>),
    RegistrationFinishResponse(Result<()>),
    KerberosInfoResponse(Result<get_kerberos_info::ResponseData>),
    SyncKerberosResponse(Result<sync_kerberos_password::ResponseData>),
}

impl CommonComponent<ChangePasswordForm> for ChangePasswordForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        use anyhow::Context;
        match msg {
            Msg::FormUpdate => Ok(true),
            Msg::KerberosInfoResponse(res) => {
                self.kerberos_info = Some(res?.kerberos_info);
                Ok(true)
            }
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                if ctx.props().is_admin {
                    self.handle_msg(ctx, Msg::SubmitNewPassword)
                } else {
                    let old_password = self.form.model().old_password.clone();
                    if old_password.is_empty() {
                        bail!("Current password required");
                    }
                    let mut rng = rand::rngs::OsRng;
                    let login_start_request = opaque::client::login::start_login(
                        &old_password,
                        &mut rng,
                    )?;
                    let req = login::ClientLoginStartRequest {
                        username: ctx.props().username.clone().into(),
                        login_start_request: login_start_request.message,
                    };
                    self.opaque_data = OpaqueData::Login(login_start_request.state);
                    self.common.call_backend(
                        ctx,
                        HostService::login_start(req),
                                             Msg::LoginStartResponse,
                    );
                    Ok(false)
                }
            }
            Msg::LoginStartResponse(res) => {
                let res = res.context("Login start failed")?;
                let login = match self.opaque_data.take() {
                    OpaqueData::Login(l) => l,
                    _ => bail!("Invalid state"),
                };
                let login_finish = opaque::client::login::finish_login(
                    login,
                    res.credential_response,
                )?;
                let req = login::ClientLoginFinishRequest {
                    server_data: res.server_data,
                    credential_finalization: login_finish.message,
                };
                self.common.call_backend(
                    ctx,
                    HostService::login_finish(req),
                                         Msg::LoginFinishResponse,
                );
                Ok(false)
            }
            Msg::LoginFinishResponse(res) => {
                res.context("Old password incorrect")?;  // Verify old pw
                self.handle_msg(ctx, Msg::SubmitNewPassword)
            }
            Msg::SubmitNewPassword => {
                let mut rng = rand::rngs::OsRng;
                let new_password = self.form.model().password.clone();
                let registration_start_request =
                opaque::client::registration::start_registration(new_password.as_bytes(), &mut rng)?;
                let req = registration::ClientRegistrationStartRequest {
                    username: ctx.props().username.clone().into(),
                    registration_start_request: registration_start_request.message,
                };
                self.opaque_data = OpaqueData::Registration(registration_start_request.state);

                // Kerberos encryption — REQUIRED (always-on, blocks on failure for sync guarantee)
                self.encrypted_password = None;
                let new_password = self.form.model().password.clone();

                if let Some(info) = &self.kerberos_info {
                    if let Some(ref pub_key) = info.public_key_der_base64 {
                        if !pub_key.is_empty() {
                            match encrypt_password(pub_key, &new_password) {
                                Ok(enc) => {
                                    log!("Encrypted pw for Kerberos sync (length): {}", enc.len());
                                    self.encrypted_password = Some(enc);
                                }
                                Err(e) => {
                                    log!("Encryption failed: {}", e.to_string());
                                    self.common.error = Some(anyhow::anyhow!("Failed to encrypt password for Kerberos sync: {}", e));
                                    return Ok(true);  // Block + show error
                                }
                            }
                        } else {
                            self.common.error = Some(anyhow::anyhow!("Kerberos public key empty—sync skipped (backend startup issue?). Contact admin."));
                            return Ok(true);  // Block change
                        }
                    } else {
                        self.common.error = Some(anyhow::anyhow!("No Kerberos public key available—sync skipped (backend update needed). Contact admin."));
                        return Ok(true);  // Block change
                    }
                } else {
                    self.common.error = Some(anyhow::anyhow!("Kerberos key info not loaded—try again."));
                    return Ok(true);
                }

                // Safety net: Require encrypted password (always-on)
                if self.encrypted_password.is_none() {
                    self.common.error = Some(anyhow::anyhow!("Kerberos encryption failed. Password change aborted."));
                    return Ok(true);
                }

                self.common.call_backend(
                    ctx,
                    HostService::register_start(req),
                                         Msg::RegistrationStartResponse,
                );
                Ok(false)
            }
            Msg::RegistrationStartResponse(res) => {
                let res = res.context("Registration start failed")?;
                let registration = match self.opaque_data.take() {
                    OpaqueData::Registration(r) => r,
                    _ => bail!("Invalid state"),
                };
                let mut rng = rand::rngs::OsRng;
                let registration_finish = opaque::client::registration::finish_registration(
                    registration,
                    res.registration_response,
                    &mut rng,
                )?;
                let req = registration::ClientRegistrationFinishRequest {
                    server_data: res.server_data,
                    registration_upload: registration_finish.message,
                };
                self.common.call_backend(
                    ctx,
                    HostService::register_finish(req),
                                         Msg::RegistrationFinishResponse,
                );
                Ok(false)
            }
            Msg::RegistrationFinishResponse(response) => {
                response.context("Registration finish failed")?;
                if let Some(enc_pw) = &self.encrypted_password {
                    let variables = sync_kerberos_password::Variables {
                        user_id: ctx.props().username.clone(),
                        encrypted_password: enc_pw.clone(),
                    };
                    self.common.call_graphql::<SyncKerberosPassword, _>(
                        ctx,
                        variables,
                        Msg::SyncKerberosResponse,
                        "Error syncing Kerberos password",
                    );
                    Ok(false)
                } else {
                    ctx.link().history().unwrap().push(AppRoute::UserDetails {
                        user_id: ctx.props().username.clone(),
                    });
                    Ok(true)
                }
            }
            Msg::SyncKerberosResponse(response) => {
                response?;
                ctx.link().history().unwrap().push(AppRoute::UserDetails {
                    user_id: ctx.props().username.clone(),
                });
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for ChangePasswordForm {
    type Message = Msg;
    type Properties = Props;

    fn create(_: &Context<Self>) -> Self {
        ChangePasswordForm {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::<FormModel>::new(FormModel::default()),
                opaque_data: OpaqueData::None,
                kerberos_info: None,
                fetched_kerberos: false,
                encrypted_password: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let is_admin = ctx.props().is_admin;
        let link = ctx.link();
        if self.kerberos_info.is_none() {
            html! { <div>{"Loading Kerberos info..."}</div> }
        } else {
            html! {
                <>
                <div class="mb-2 mt-2">
                <h5 class="fw-bold">{"Change password"}</h5>
                </div>
                { if let Some(e) = &self.common.error {
                    html! { <div class="alert alert-danger mt-3 mb-3">{e.to_string()}</div> }
                } else { html! {} }}
                <form class="form">
                { if !is_admin {
                    html! {
                        <Field<FormModel>
                        form={&self.form}
                        required=true
                        label="Current password"
                        field_name="old_password"
                        input_type="password"
                        autocomplete="current-password"
                        oninput={link.callback(|_| Msg::FormUpdate)} />
                    }
                } else { html! {} }}
                <Field<FormModel>
                form={&self.form}
                required=true
                label="New password"
                field_name="password"
                input_type="password"
                autocomplete="new-password"
                oninput={link.callback(|_| Msg::FormUpdate)} />
                <Field<FormModel>
                form={&self.form}
                required=true
                label="Confirm password"
                field_name="confirm_password"
                input_type="password"
                autocomplete="new-password"
                oninput={link.callback(|_| Msg::FormUpdate)} />
                <Submit
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})}
                text="Save changes">
                <Link
                classes="btn btn-secondary ms-2 col-auto col-form-label"
                to={AppRoute::UserDetails{user_id: ctx.props().username.clone()}}>
                <i class="bi-arrow-return-left me-2"></i>{"Back"}
                </Link>
                </Submit>
                </form>
                </>
            }
        }
    }

    fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
        if first_render && !self.fetched_kerberos {
            console_log!("Fetching Kerberos info for password change");
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
