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
        encrypt::encrypt_password,
        schema::AttributeType,
    },
};
use anyhow::{Result, bail};
use graphql_client::GraphQLQuery;
use lldap_auth::{opaque, registration};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};
use yew::Context as YewContext;

fn attribute_priority(name: &str) -> (i32, String) {
    let priorities = vec![
        "firstname",
        "lastname",
        "displayname",
        "mail",
        "avatar",
        "uidnumber",
        "gidnumber",
        "loginshell",
    ];
    let index = priorities.iter().position(|&p| p == name).map(|i| i as i32).unwrap_or(100);
    (index, name.to_lowercase())  // Tuple for stable sort (priority then alpha)
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

#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "queries/create_user.graphql",
response_derives = "Debug,Clone",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateUser;

use create_user::AttributeValueInput as GraphQLAttributeValue;

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
            fetched_schema: bool,
            encrypted_password: Option<String>,
            user_id: Option<String>,
            opaque_data: Option<opaque::client::registration::ClientRegistration>,
            kerberos_info: Option<get_kerberos_info::GetKerberosInfoKerberosInfo>,
            kerberossync_enabled: bool,
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
    SuccessfulCreation,
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStartResponse>>),
    RegistrationFinishResponse(Result<()>),
    SyncKerberosResponse(Result<sync_kerberos_password::ResponseData>),
    ToggleKerberosSync(bool),
}

impl CommonComponent<CreateUserForm> for CreateUserForm {
    fn handle_msg(
        &mut self,
        ctx: &YewContext<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        use anyhow::Context;
        match msg {
            Msg::Update => Ok(true),
            Msg::ListAttributesResponse(schema) => {
                self.attributes_schema =
                Some(schema?.schema.user_schema.attributes.into_iter().collect());
                self.common.call_graphql::<GetKerberosInfo, _>(
                    ctx,
                    get_kerberos_info::Variables {},
                    Msg::KerberosInfoResponse,
                    "Error trying to fetch Kerberos info",
                );
                Ok(true)
            }
            Msg::KerberosInfoResponse(res) => {
                self.kerberos_info = Some(res?.kerberos_info);
                Ok(true)
            }
            Msg::ToggleKerberosSync(enabled) => {
                self.kerberossync_enabled = enabled;
                Ok(true)
            }
            Msg::SubmitForm => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }

                self.encrypted_password = None;
                let model = self.form.model();
                let new_password = model.password.clone();

                // Encrypt password unconditionally (cheap, and keeps code simple)
                // We'll only use it later if sync is enabled
                if let Some(info) = &self.kerberos_info {
                    if let Some(ref pub_key_der_base64) = info.public_key_der_base64 {
                        match encrypt_password(pub_key_der_base64, &new_password) {
                            Ok(encrypted) => {
                                self.encrypted_password = Some(encrypted);
                            }
                            Err(e) => {
                                bail!("Failed to encrypt password for Kerberos sync: {}", e);
                            }
                        }
                    } else {
                        bail!("Kerberos enabled but no public key available—check backend startup/logs and restart container if needed");
                    }
                } else {
                    bail!("Kerberos info not loaded—try reloading or restart container");
                }

                // Strict require encrypted (blocks if missing/fail)
                if self.encrypted_password.is_none() {
                    bail!("Kerberos password encryption failed—user creation aborted (fix backend/restart container)");
                }

                let all_values = read_all_form_attributes(
                    self.attributes_schema.iter().flatten(),
                                                          &self.form_ref,
                                                          IsAdmin(true),
                                                          EmailIsRequired(true),
                )?;  // Unwrap Result with ? (propagates error to banner if form read fails)

                // Make mutable so we can conditionally add kerberossync="0"
                let mut attributes = all_values
                .into_iter()  // Owned AttributeValue elements (move name/values)
                .filter(|a| !a.values.is_empty())
                .map(|a| GraphQLAttributeValue {
                    name: a.name,
                    value: a.values,  // Local plural 'values' moves to GraphQL singular 'value'
                })
                .collect::<Vec<_>>();

                // If sync disabled, explicitly send kerberossync="0" to override backend default
                if !self.kerberossync_enabled {
                    attributes.push(GraphQLAttributeValue {
                        name: "kerberossync".to_string(),
                                    value: vec!["0".to_string()],
                    });
                }

                let user = create_user::CreateUserInput {
                    id: model.username,
                    displayName: None,
                    firstName: None,
                    lastName: None,
                    avatar: None,
                    email: None,
                    attributes: Some(attributes),
                };
                let variables = create_user::Variables { user };
                self.common.call_graphql::<CreateUser, _>(
                    ctx,
                    variables,
                    Msg::CreateUserResponse,
                    "Error trying to create user",
                );
                Ok(true)
            }
            Msg::CreateUserResponse(res) => {
                self.user_id = Some(res?.create_user.id);
                if self.form.model().password.is_empty() {
                    return self.handle_msg(ctx, Msg::SuccessfulCreation);
                }
                let mut rng = rand::rngs::OsRng;
                let registration_start_request = opaque::client::registration::start_registration(
                    self.form.model().password.as_bytes(),
                                                                                                  &mut rng,
                )
                .context("Could not initiate registration")?;
                let req = registration::ClientRegistrationStartRequest {
                    username: self.user_id.clone().unwrap().into(),
                    registration_start_request: registration_start_request.message,
                };
                self.opaque_data = Some(registration_start_request.state);
                self.common.call_backend(
                    ctx,
                    HostService::register_start(req),
                                         Msg::RegistrationStartResponse,
                );
                Ok(false)
            }
            Msg::RegistrationStartResponse(res) => {
                let res = res.context("Could not initiate registration")?;
                let registration = self.opaque_data.take().expect("Missing registration data");
                let mut rng = rand::rngs::OsRng;
                let registration_finish = opaque::client::registration::finish_registration(
                    registration,
                    res.registration_response,
                    &mut rng,
                )
                .context("Error during registration")?;
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
                response?;
                // Only sync if checkbox was enabled AND we have an encrypted password
                if self.kerberossync_enabled {
                    if let Some(enc_pw) = &self.encrypted_password {
                        let variables = sync_kerberos_password::Variables {
                            user_id: self.user_id.clone().unwrap(),
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
                        // Shouldn't happen, but fall back to success
                        self.handle_msg(ctx, Msg::SuccessfulCreation)
                    }
                } else {
                    // Sync disabled → go straight to success
                    self.handle_msg(ctx, Msg::SuccessfulCreation)
                }
            }
            Msg::SyncKerberosResponse(response) => {
                response?.sync_kerberos_password;
                self.handle_msg(ctx, Msg::SuccessfulCreation)
            }
            Msg::SuccessfulCreation => {
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
                    encrypted_password: None,
                    user_id: None,
                    opaque_data: None,
                    kerberossync_enabled: true,
        }
    }

    fn update(&mut self, ctx: &YewContext<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &YewContext<Self>) -> Html {
        let link = ctx.link();
        if self.attributes_schema.is_none() || self.kerberos_info.is_none() {
            html! {
                <div>{"Loading schema and Kerberos info..."}</div>
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
                    (|| {
                        let attrs = self.attributes_schema.as_ref().unwrap();
                        let mut indices: Vec<usize> = (0..attrs.len())
                        .filter(|&i| !attrs[i].is_readonly && attrs[i].name != "kerberossync")
                        .collect();
                        indices.sort_by_key(|&i| attribute_priority(&attrs[i].name));
                        indices
                        .into_iter()
                        .map(|i| get_custom_attribute_input(&attrs[i]))
                        .collect::<Vec<Html>>()
                    })()
                }
                // NEW: Kerberos sync checkbox — placed here for good UX flow
                <div class="mb-3 form-check">
                <input
                type="checkbox"
                class="form-check-input"
                id="kerberossync_checkbox"
                checked={self.kerberossync_enabled}
                onchange={ctx.link().callback(|e: Event| {
                    let checked = e.target_unchecked_into::<web_sys::HtmlInputElement>().checked();
                    Msg::ToggleKerberosSync(checked)
                })}
                />
                <label class="form-check-label" for="kerberossync_checkbox">
                {"Kerberos Sync"}
                <button data-bs-placement="right" title="Sync Kerberos principal and password for SSO." type="button" class="btn btn-sm btn-link" aria-label="Kerberos Sync Info">
                <i aria-label="Info" class="bi bi-info-circle"></i>
                </button>
                </label>
                </div>
                // End new checkbox
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
            gloo_console::log!("Rendered: fetching schema");
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
