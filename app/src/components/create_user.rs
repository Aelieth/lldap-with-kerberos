use crate::{
    components::{
        form::{
            attribute_input::{ListAttributeInput, SingleAttributeInput},
            field::Field,
            submit::Submit,
        },
        router::AppRoute,
    },
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
        form_utils::{
            EmailIsRequired, GraphQlAttributeSchema, IsAdmin,
            read_all_form_attributes,
        },
        obfuscate::obfuscate_password,
        schema::AttributeType,
    },
};
use anyhow::{Result, ensure, bail};
use graphql_client::GraphQLQuery;
use gloo_console::log;
use lldap_auth::{opaque, registration};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};
use anyhow::Context as AnyhowContext;
use yew::Context as YewContext;

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
pub struct SyncKerberos;

#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "queries/create_user.graphql",
response_derives = "Debug,Clone",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateUser;

#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "queries/get_user_attributes_schema.graphql",
response_derives = "Debug,Clone,PartialEq,Eq",
custom_scalars_module = "crate::infra::graphql",
extern_enums("AttributeType")
)]
pub struct GetUserAttributesSchema;

pub type Attribute = get_user_attributes_schema::GetUserAttributesSchemaSchemaUserSchemaAttributes;

impl From<&Attribute> for GraphQlAttributeSchema {
    fn from(attr: &Attribute) -> Self {
        Self {
            name: attr.name.clone(),
            is_list: attr.is_list,
            is_readonly: attr.is_readonly,
            is_editable: attr.is_editable,
        }
    }
}

pub struct CreateUserForm {
    common: CommonComponentParts<Self>,
    form: yew_form::Form<CreateUserModel>,
        attributes_schema: Option<Vec<Attribute>>,
        form_ref: NodeRef,
            kerberos_info: Option<get_kerberos_info::GetKerberosInfoKerberosInfo>,
            fetched_schema: bool,
            fetched_kerberos: bool,
            obfuscated_password: Option<String>,
            user_id: Option<String>,
}

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct CreateUserModel {
    #[validate(length(min = 1, message = "Username is required"))]
    username: String,
    #[validate(custom(
    function = "empty_or_long",
    message = "Password should be longer than 8 characters (or left empty)"
    ))]
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

pub enum Msg {
    Update,
    ListAttributesResponse(Result<get_user_attributes_schema::ResponseData>),
    KerberosInfoResponse(Result<get_kerberos_info::ResponseData>),
    SubmitForm,
    CreateUserResponse(Result<create_user::ResponseData>),
    RegistrationStartResponse(
        (
            opaque::client::registration::ClientRegistration,
         Result<Box<registration::ServerRegistrationStartResponse>>,
        ),
    ),
    RegistrationFinishResponse(Result<()>),
    SyncKerberosResponse(Result<sync_kerberos::ResponseData>),
}

impl CommonComponent<CreateUserForm> for CreateUserForm {
    fn handle_msg(
        &mut self,
        ctx: &YewContext<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        use AnyhowContext;
        match msg {
            Msg::Update => Ok(true),
            Msg::ListAttributesResponse(response) => {
                let data: get_user_attributes_schema::ResponseData = response?;
                self.attributes_schema = Some(data.schema.user_schema.attributes);
                if !self.fetched_kerberos {
                    log!("Fetching Kerberos info after schema");
                    self.common.call_graphql::<GetKerberosInfo, _>(
                        ctx,
                        get_kerberos_info::Variables {},
                        Msg::KerberosInfoResponse,
                        "Error trying to fetch Kerberos info",
                    );
                    self.fetched_kerberos = true;
                }
                Ok(true)
            }
            Msg::KerberosInfoResponse(response) => {
                let data: get_kerberos_info::ResponseData = response?;
                self.kerberos_info = Some(data.kerberos_info);
                Ok(true)
            }
            Msg::SubmitForm => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let model = self.form.model();
                ensure!(
                    model.password == model.confirm_password,
                    "Passwords don't match"
                );
                let schema_iter = self.attributes_schema.as_ref().unwrap().iter().map(|a| GraphQlAttributeSchema::from(a));
                let attributes = read_all_form_attributes(
                    schema_iter,
                    &self.form_ref,
                    IsAdmin(true),
                                                          EmailIsRequired(true),
                )?;
                let attributes_input = attributes
                .iter()
                .map(|attr| create_user::AttributeValueInput {
                    name: attr.name.clone(),
                     value: attr.values.clone(),
                })
                .collect::<Vec<_>>();
                let obfuscated_password = if !model.password.is_empty() {
                    if let Some(kerberos_info) = &self.kerberos_info {
                        if kerberos_info.enabled {
                            Some(obfuscate_password(
                                &model.password,
                                kerberos_info.encode_key.as_ref().unwrap_or(&String::new()).as_str(),
                            ))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                self.obfuscated_password = obfuscated_password.clone();
                let user_input = create_user::CreateUserInput {
                    id: model.username.clone(),
                    email: None,
                    displayName: None,
                    firstName: None,
                    lastName: None,
                    avatar: None,
                    attributes: Some(attributes_input),
                };
                let variables = create_user::Variables {
                    user: user_input,
                };
                self.common.call_graphql::<CreateUser, _>(
                    ctx,
                    variables,
                    Msg::CreateUserResponse,
                    "Error trying to create user",
                );
                Ok(true)
            }
            Msg::CreateUserResponse(response) => {
                let data: create_user::ResponseData = response?;
                self.user_id = Some(data.create_user.id.clone());
                if self.obfuscated_password.is_some() {
                    let mut rng = rand::rngs::OsRng;
                    let registration_start_request =
                    opaque::client::registration::start_registration(
                        self.form.model().password.as_bytes(),
                                                                     &mut rng,
                    )?;
                    let req = registration::ClientRegistrationStartRequest {
                        username: self.form.model().username.clone().into(),
                        registration_start_request: registration_start_request.message,
                    };
                    self.common.call_backend(
                        ctx,
                        async move {
                            (
                                registration_start_request.state,
                             HostService::register_start(req).await,
                            )
                        },
                        Msg::RegistrationStartResponse,
                    );
                } else {
                    ctx.link().history().unwrap().push(AppRoute::ListUsers);
                }
                Ok(true)
            }
            Msg::RegistrationStartResponse((state, res)) => {
                let res = res.context("Could not initiate registration")?;
                let mut rng = rand::rngs::OsRng;
                let registration_finish = opaque::client::registration::finish_registration(
                    state,
                    res.registration_response,
                    &mut rng,
                )
                .context("Could not finalize registration")?;
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
                response?;
                if let Some(obfuscated_password) = self.obfuscated_password.take() {
                    if let Some(user_id) = self.user_id.clone() {
                        self.common.call_graphql::<SyncKerberos, _>(
                            ctx,
                            sync_kerberos::Variables {
                                user_id,
                                obfuscated_password,
                            },
                            Msg::SyncKerberosResponse,
                            "Error syncing Kerberos",
                        );
                    }
                } else {
                    ctx.link().history().unwrap().push(AppRoute::ListUsers);
                }
                Ok(true)
            }
            Msg::SyncKerberosResponse(response) => {
                response?;
                ctx.link().history().unwrap().push(AppRoute::ListUsers);
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for CreateUserForm {
    type Message = Msg;
    type Properties = ();

    fn create(_: &YewContext<Self>) -> Self {
        CreateUserForm {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::<CreateUserModel>::new(CreateUserModel::default()),
                attributes_schema: None,
                form_ref: NodeRef::default(),
                    kerberos_info: None,
                    fetched_schema: false,
                    fetched_kerberos: false,
                    obfuscated_password: None,
                    user_id: None,
        }
    }

    fn update(&mut self, ctx: &YewContext<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &YewContext<Self>) -> Html {
        let link = ctx.link();
        if self.attributes_schema.is_none() {
            html! {
                <div>{"Loading schema..."}</div>
            }
        } else {
            html! {
                <div class="row justify-content-center">
                <form class="form py-3" ref={self.form_ref.clone()}>
                <Field<CreateUserModel>
                form={&self.form}
                required=true
                label="User name"
                field_name="username"
                oninput={link.callback(|_| Msg::Update)} />
                {
                    self.attributes_schema.as_ref().unwrap()
                    .iter()
                    .filter(|a| !a.is_readonly)
                    .map(get_custom_attribute_input)
                    .collect::<Vec<_>>()
                }
                <Field<CreateUserModel>
                form={&self.form}
                label="Password"
                field_name="password"
                input_type="password"
                autocomplete="new-password"
                oninput={link.callback(|_| Msg::Update)} />
                <Field<CreateUserModel>
                form={&self.form}
                label="Confirm password"
                field_name="confirm_password"
                input_type="password"
                autocomplete="new-password"
                oninput={link.callback(|_| Msg::Update)} />
                <Submit
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitForm})} />
                </form>
                {
                    if let Some(e) = &self.common.error {
                        html! {
                            <div class="alert alert-danger">
                            {e.to_string() }
                            </div>
                        }
                    } else { html! {} }
                }
                </div>
            }
        }
    }

    fn rendered(&mut self, ctx: &YewContext<Self>, first_render: bool) {
        if first_render && !self.fetched_schema {
            log!("Rendered: fetching schema");
            self.common.call_graphql::<GetUserAttributesSchema, _>(
                ctx,
                get_user_attributes_schema::Variables {},
                Msg::ListAttributesResponse,
                "Error trying to fetch user schema",
            );
            self.fetched_schema = true;
        }
    }
}

fn get_custom_attribute_input(attribute_schema: &Attribute) -> Html {
    let mail_is_required = attribute_schema.name.as_str() == "mail";

    if attribute_schema.is_list {
        html! {
            <ListAttributeInput
            name={attribute_schema.name.clone()}
            attribute_type={attribute_schema.attribute_type}
            required={mail_is_required}
            />
        }
    } else {
        html! {
            <SingleAttributeInput
            name={attribute_schema.name.clone()}
            attribute_type={attribute_schema.attribute_type}
            required={mail_is_required}
            />
        }
    }
}
