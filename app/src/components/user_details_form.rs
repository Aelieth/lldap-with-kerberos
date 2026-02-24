use crate::{
    components::{
        form::{
            attribute_input::{ListAttributeInput, SingleAttributeInput},
            static_value::StaticValue,
            submit::Submit,
        },
        user_details::{Attribute, AttributeSchema, User},
    },
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        form_utils::{AttributeValue, EmailIsRequired, IsAdmin, read_all_form_attributes},
            schema::AttributeType,
    },
};
use anyhow::Result;
use chrono::NaiveDateTime;
use graphql_client::GraphQLQuery;
use yew::prelude::*;

/// The GraphQL query sent to the server to update the user details.
#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "queries/update_user.graphql",
response_derives = "Debug",
variables_derives = "Clone,PartialEq,Eq",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct UpdateUser;

fn attribute_priority(name: &str) -> (i32, String) {
    let priorities = vec![
        "firstname",
        "lastname",
        "displayname",
        "mail",
        "avatar",
        "uidnumber",
        "gidnumber",
        "homedirectory",
        "loginshell",
    ];
    let index = priorities.iter().position(|&p| p == name).map(|i| i as i32).unwrap_or(100);
    (index, name.to_lowercase())
}

pub struct UserDetailsForm {
    common: CommonComponentParts<Self>,
    just_updated: bool,
    user: User,
    form_ref: NodeRef,
        kerberossync_enabled: bool,
        show_kerberos_banner: bool,
}

pub enum Msg {
    Update,
    SubmitClicked,
    UserUpdated(Result<update_user::ResponseData>),
    ToggleKerberosSync(bool),
}

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub user: User,
    pub user_attributes_schema: Vec<AttributeSchema>,
    pub is_admin: bool,
    pub is_edited_user_admin: bool,
}

impl CommonComponent<UserDetailsForm> for UserDetailsForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::SubmitClicked => Ok(self.submit_user_update_form(ctx)),
            Msg::UserUpdated(response) => {
                if response.is_ok() {
                    self.show_kerberos_banner = false;
                    self.just_updated = true;
                }
                Ok(true)
            }
            Msg::ToggleKerberosSync(value) => {
                self.kerberossync_enabled = value;
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for UserDetailsForm {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let kerberossync_enabled = ctx.props().user.attributes.iter()
        .any(|attr| attr.name == "kerberossync" && attr.value == vec!["1"]);
        Self {
            common: CommonComponentParts::<Self>::create(),
            just_updated: false,
            user: ctx.props().user.clone(),
            form_ref: NodeRef::default(),
                kerberossync_enabled,
                show_kerberos_banner: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.just_updated = false;
        match msg {
            Msg::Update => true,
            Msg::SubmitClicked => self.submit_user_update_form(ctx),
            Msg::UserUpdated(response) => {
                if response.is_ok() {
                    self.just_updated = true;
                    self.show_kerberos_banner = false;   // hide banner after successful save
                }
                true
            }
            Msg::ToggleKerberosSync(value) => {
                self.kerberossync_enabled = value;
                self.show_kerberos_banner = value;   // banner appears ONLY when turned ON
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let is_admin = ctx.props().is_admin;

        let can_edit = |a: &AttributeSchema| !a.is_readonly && (is_admin || a.is_editable);

        let display_field = |a: &AttributeSchema| {
            if can_edit(a) {
                get_custom_attribute_input(a, &self.user.attributes)
            } else {
                get_custom_attribute_static(a, &self.user.attributes)
            }
        };

        let mut all_attrs: Vec<&AttributeSchema> = ctx.props().user_attributes_schema
        .iter()
        .filter(|a| a.name != "user_id" && a.name != "kerberossync")
        .collect();
        all_attrs.sort_by_key(|a| attribute_priority(&a.name));

        html! {
            <div class="py-3">
            <form class="form" ref={self.form_ref.clone()}>
            <StaticValue label="User ID" id="userId">
            <i>{&self.user.id}</i>
            </StaticValue>

            { all_attrs.iter().map(|&a| display_field(a)).collect::<Vec<_>>() }

            { if is_admin {
                html! {
                    <div class="mb-3 row">
                    <label class="form-label col-4 col-form-label" for="kerberossync_toggle">
                    {"Kerberos Sync"}
                    <button data-bs-placement="right" title="Sync Kerberos principal and password for SSO with KDE/GNOME." type="button" class="btn btn-sm btn-link" aria-label="Kerberos Sync Info">
                    <i aria-label="Info" class="bi bi-info-circle"></i>
                    </button>
                    </label>
                    <div class="col-8 d-flex align-items-center">
                    <div class="btn-group" role="group" style="width: 120px;">
                    <button type="button" class={classes!("btn", "btn-outline-primary", if self.kerberossync_enabled { "active" } else { "" })} onclick={link.callback(|_| Msg::ToggleKerberosSync(true))}>
                    {"On"}
                    </button>
                    <button type="button" class={classes!("btn", "btn-outline-secondary", if !self.kerberossync_enabled { "active" } else { "" })} onclick={link.callback(|_| Msg::ToggleKerberosSync(false))}>
                    {"Off"}
                    </button>
                    </div>
                    <div class="form-text text-muted ms-3">
                    {"ON = sync principal on next password change. OFF = delete principal immediately."}
                    </div>
                    </div>

                    // Flash banner — appears only when toggled to ON
                    { if self.show_kerberos_banner {
                        html! {
                            <div class="alert alert-info mt-2">
                            {"After Save Changes "}{&self.user.id}{" password must be changed by admin or self to finish the sync."}
                            </div>
                        }
                    } else { html! {} }}
                    </div>
                }
            } else { html! {} }}

            <Submit
            text="Save changes"
            disabled={self.common.is_task_running()}
            onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitClicked})} />
            </form>

            { if let Some(e) = &self.common.error {
                html! { <div class="alert alert-danger">{e.to_string()}</div> }
            } else { html! {} }}

            <div hidden={!self.just_updated}>
            <div class="alert alert-success mt-4">{"User successfully updated!"}</div>
            </div>
            </div>
        }
    }
}

impl UserDetailsForm {
    fn submit_user_update_form(&mut self, ctx: &Context<Self>) -> bool {
        let mut all_values = read_all_form_attributes(
            ctx.props().user_attributes_schema.iter(),
                                                      &self.form_ref,
                                                      IsAdmin(ctx.props().is_admin),
                                                      EmailIsRequired(!ctx.props().is_edited_user_admin),
        ).unwrap_or_default();

        let base_attributes = &self.user.attributes;
        all_values.retain(|a| {
            let base_val = base_attributes.iter().find(|base_val| base_val.name == a.name);
            base_val.map(|v| v.value != a.values).unwrap_or(!a.values.is_empty())
        });

        all_values.retain(|a| a.name != "kerberossync");
        all_values.push(AttributeValue {
            name: "kerberossync".to_string(),
                        values: vec![if self.kerberossync_enabled { "1" } else { "0" }.to_string()],
        });

        let remove_attributes: Option<Vec<String>> = if all_values.is_empty() {
            None
        } else {
            Some(all_values.iter().map(|a| a.name.clone()).collect())
        };

        let insert_attributes: Option<Vec<update_user::AttributeValueInput>> = if remove_attributes.is_none() {
            None
        } else {
            Some(
                all_values
                .into_iter()
                .filter(|a| !a.values.is_empty())
                .map(|AttributeValue { name, values }| update_user::AttributeValueInput {
                    name,
                    value: values,
                })
                .collect(),
            )
        };

        let mut user_input = update_user::UpdateUserInput {
            id: self.user.id.clone(),
            email: None,
            displayName: None,
            firstName: None,
            lastName: None,
            avatar: None,
            removeAttributes: None,
            insertAttributes: None,
        };
        let default_user_input = user_input.clone();
        user_input.removeAttributes = remove_attributes;
        user_input.insertAttributes = insert_attributes;

        if user_input == default_user_input {
            return false;
        }

        let req = update_user::Variables { user: user_input };
        self.common.call_graphql::<UpdateUser, _>(
            ctx,
            req,
            Msg::UserUpdated,
            "Error trying to update user",
        );
        false
    }
}

fn get_custom_attribute_input(
    attribute_schema: &AttributeSchema,
    user_attributes: &[Attribute],
) -> Html {
    let values = user_attributes
    .iter()
    .find(|a| a.name == attribute_schema.name)
    .map(|attribute| attribute.value.clone())
    .unwrap_or_default();

    if attribute_schema.is_list {
        html! {
            <ListAttributeInput
            name={attribute_schema.name.clone()}
            attribute_type={attribute_schema.attribute_type}
            values={values}
            />
        }
    } else {
        html! {
            <SingleAttributeInput
            name={attribute_schema.name.clone()}
            attribute_type={attribute_schema.attribute_type}
            value={values.first().cloned().unwrap_or_default()}
            />
        }
    }
}

fn get_custom_attribute_static(
    attribute_schema: &AttributeSchema,
    user_attributes: &[Attribute],
) -> Html {
    let values = user_attributes
    .iter()
    .find(|a| a.name == attribute_schema.name)
    .map(|attribute| attribute.value.clone())
    .unwrap_or_default();

    let value_to_str = match attribute_schema.attribute_type {
        AttributeType::String | AttributeType::Integer => |v: String| v,
        AttributeType::DateTime => |v: String| {
            if let Ok(dt) = NaiveDateTime::parse_from_str(&v, "%Y-%m-%d %H:%M:%S%.f") {
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&v) {
                dt.naive_utc().format("%Y-%m-%d %H:%M:%S").to_string()
            } else {
                v
            }
        },
        AttributeType::JpegPhoto => |_: String| "JPEG photo".to_string(),
    };

    html! {
        <StaticValue label={attribute_schema.name.clone()} id={attribute_schema.name.clone()}>
        {values.into_iter().map(|x| html!{<div>{value_to_str(x)}</div>}).collect::<Vec<_>>()}
        </StaticValue>
    }
}
