use crate::{
    components::{
        router::{AppRoute, Link},
        user_ou_table::UserOuTable,
        change_user_ou::ChangeUserOu,
        delete_user::DeleteUser,
    },
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use list_users_query::ResponseData;
use list_user_ous_query::ResponseData as OusResponseData;
use yew::prelude::*;
use wasm_bindgen::JsCast;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_user_ous.graphql",
    response_derives = "Debug, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListUserOusQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_users.graphql",
    response_derives = "Debug, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListUsersQuery;

type User = list_users_query::ListUsersQueryUsers;

pub struct UserTable {
    common: CommonComponentParts<Self>,
    users: Option<Vec<User>>,
    ou_filter: String,
    search_term: String,
    search_field: String,
    ous: Vec<String>,
    selected_users: Vec<String>,
}

pub enum Msg {
    ListUsersResponse(Result<ResponseData>),
    ListUserOusResponse(Result<OusResponseData>),
    OnUserDeleted(String),
    OnError(Error),
    OuFilterChanged(String),
    SearchTermChanged(String),
    SearchFieldChanged(String),
    ToggleUserSelection(String),
    ToggleSelectAll,
    OuCreated(String),
    OuDeleted(String),
    CreateNewUser,
    ChangeOuForSelected(String),
    DeleteSelected,
    CreateOuError(String),
}

impl CommonComponent<UserTable> for UserTable {
    fn handle_msg(&mut self, _ctx: &Context<Self>, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::ListUsersResponse(users) => {
                self.users = Some(users?.users.into_iter().collect());
                Ok(true)
            }
            Msg::ListUserOusResponse(ous) => {
                self.ous = ous?.user_ous;
                Ok(true)
            }
            Msg::OnError(e) => Err(e),
            Msg::CreateOuError(err) => {
                self.common.error = Some(anyhow::Error::msg(err));
                Ok(true)
            }
            Msg::OnUserDeleted(user_id) => {
                if let Some(users) = &mut self.users {
                    users.retain(|u| u.id != user_id);
                }
                self.selected_users.retain(|id| id != &user_id);
                Ok(true)
            }
            Msg::OuFilterChanged(ou) => {
                self.ou_filter = ou;
                Ok(true)
            }
            Msg::SearchTermChanged(term) => {
                self.search_term = term;
                Ok(true)
            }
            Msg::SearchFieldChanged(field) => {
                self.search_field = field;
                Ok(true)
            }
            Msg::ToggleUserSelection(user_id) => {
                if self.selected_users.contains(&user_id) {
                    self.selected_users.retain(|id| id != &user_id);
                } else {
                    self.selected_users.push(user_id);
                }
                Ok(true)
            }
            Msg::ToggleSelectAll => {
                if let Some(users) = &self.users {
                    let mut filtered = users.clone();
                    if self.ou_filter != "All" {
                        filtered.retain(|u| Self::get_ou(u) == self.ou_filter);
                    }
                    if !self.search_term.is_empty() {
                        let term = self.search_term.to_lowercase();
                        filtered.retain(|u| match self.search_field.as_str() {
                            "User ID" => u.id.to_lowercase().contains(&term),
                            "Email" => u.email.to_lowercase().contains(&term),
                            "Display Name" => u.display_name.to_lowercase().contains(&term),
                            "First Name" => Self::get_attribute_value(u, "firstname").unwrap_or_default().to_lowercase().contains(&term),
                            "Last Name" => Self::get_attribute_value(u, "lastname").unwrap_or_default().to_lowercase().contains(&term),
                            _ => true,
                        });
                    }
                    let filtered_ids: Vec<String> = filtered.iter().map(|u| u.id.clone()).collect();
                    if self.selected_users.len() == filtered_ids.len() && !filtered_ids.is_empty() {
                        self.selected_users.clear();
                    } else {
                        self.selected_users = filtered_ids;
                    }
                }
                Ok(true)
            }
            Msg::OuCreated(new_ou) => {
                if !new_ou.trim().is_empty() && !self.ous.contains(&new_ou) {
                    self.ous.push(new_ou);
                }
                Ok(true)
            }
            Msg::OuDeleted(deleted_ou) => {
                self.ous.retain(|o| o != &deleted_ou);
                if self.ou_filter == deleted_ou {
                    self.ou_filter = "All".to_string();
                }
                Ok(true)
            }
            Msg::CreateNewUser => {
                web_sys::console::log_1(&"Creating new user - navigate to create form".into());
                Ok(true)
            }
            Msg::ChangeOuForSelected(new_ou) => {
                if self.selected_users.is_empty() || new_ou == "All" {
                    return Ok(true);
                }
                let confirm_msg = format!(
                    "Change {} selected user(s) to OU '{}'?\n\nThis cannot be undone.",
                    self.selected_users.len(),
                    new_ou
                );
                if web_sys::window()
                    .and_then(|w| w.confirm_with_message(&confirm_msg).ok())
                    .unwrap_or(false)
                {
                    web_sys::console::log_1(&format!("Moving {} users to OU: {}", self.selected_users.len(), new_ou).into());
                    self.selected_users.clear();
                }
                Ok(true)
            }
            Msg::DeleteSelected => {
                if self.selected_users.is_empty() {
                    return Ok(true);
                }
                let count = self.selected_users.len();
                let confirm_msg = format!(
                    "Are you sure you want to delete {} selected user(s)?\n\nThis cannot be undone.",
                    count
                );
                if web_sys::window()
                    .and_then(|w| w.confirm_with_message(&confirm_msg).ok())
                    .unwrap_or(false)
                {
                    web_sys::console::log_1(&format!("Bulk deleting {} users: {:?}", count, self.selected_users).into());
                    if let Some(users) = &mut self.users {
                        users.retain(|u| !self.selected_users.contains(&u.id));
                    }
                    self.selected_users.clear();
                }
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl UserTable {
    fn get_attribute_value(user: &User, name: &str) -> Option<String> {
        user.attributes
            .iter()
            .find(|a| a.name == name)
            .and_then(|a| a.value.first().cloned())
    }

    fn get_kerberos_sync(user: &User) -> bool {
        Self::get_attribute_value(user, "kerberossync")
            .and_then(|v| v.parse::<i64>().ok())
            .map_or(false, |i| i != 0)
    }

    fn get_ou(user: &User) -> String {
        Self::get_attribute_value(user, "ou").unwrap_or_else(|| "people".to_string())
    }
}

impl Component for UserTable {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = UserTable {
            common: CommonComponentParts::<Self>::create(),
            users: None,
            ou_filter: "All".to_string(),
            search_term: String::new(),
            search_field: "User ID".to_string(),
            ous: vec![],
            selected_users: Vec::new(),
        };

        table.common.call_graphql::<ListUsersQuery, _>(
            ctx,
            list_users_query::Variables { filters: None },
            Msg::ListUsersResponse,
            "Error trying to fetch users",
        );

        table.common.call_graphql::<ListUserOusQuery, _>(
            ctx,
            list_user_ous_query::Variables {},
            Msg::ListUserOusResponse,
            "Error trying to fetch OUs",
        );

        table
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div>
            <UserOuTable
            ou_filter={self.ou_filter.clone()}
            ous={self.ous.clone()}
            on_ou_changed={ctx.link().callback(Msg::OuFilterChanged)}
            on_ou_created={ctx.link().callback(Msg::OuCreated)}
            on_ou_deleted={ctx.link().callback(Msg::OuDeleted)}
            error={self.common.error.as_ref().map(|e| e.to_string())}
            />
            <hr class="my-4" />

            <div class="row g-3 align-items-end mb-3">
            <div class="col-auto">
            <Link classes="btn btn-primary" to={AppRoute::CreateUser}>
            <i class="bi-person-plus me-2"></i>
            {"Create User"}
            </Link>
            </div>
            <div class="col-auto">
            <ChangeUserOu
            selected_users={self.selected_users.clone()}
            on_ou_changed={ctx.link().callback(|new_ou: String| Msg::ChangeOuForSelected(new_ou))}
            on_error={Callback::noop()} />
            </div>

            <div class="col-md-2 ms-auto">
            <select class="form-select" onchange={ctx.link().callback(|e: Event| {
                let value = e.target().unwrap()
                .dyn_into::<web_sys::HtmlSelectElement>().unwrap()
                .value();
                Msg::SearchFieldChanged(value)
            })}>
            { for vec!["User ID".to_string(), "Email".to_string(), "Display Name".to_string(), "First Name".to_string(), "Last Name".to_string(), "Creation Date".to_string()].iter().map(|f| html! {
                <option value={f.clone()} selected={f == &self.search_field}>{f}</option>
            }) }
            </select>
            </div>
            <div class="col-md-4">
            <input type="text" class="form-control" placeholder="Type to search..." value={self.search_term.clone()}
            oninput={ctx.link().callback(|e: InputEvent| {
                let value = e.target().unwrap()
                .dyn_into::<web_sys::HtmlInputElement>().unwrap()
                .value();
                Msg::SearchTermChanged(value)
            })} />
            </div>
            </div>

            {self.view_users(ctx)}

            <div class="row justify-content-start mt-3">
            <div class="col-auto">
            <DeleteUser
            username={format!("{} selected users", self.selected_users.len())}
            on_user_deleted={ctx.link().callback(|_| Msg::DeleteSelected)}
            on_error={Callback::noop()} />
            </div>
            </div>

            {self.view_errors()}
            </div>
        }
    }
}

impl UserTable {
    fn view_users(&self, ctx: &Context<Self>) -> Html {
        let filtered_users = self.users.as_ref().map_or(vec![], |users| {
            let mut filtered = users.clone();
            if self.ou_filter != "All" {
                filtered.retain(|u| Self::get_ou(u) == self.ou_filter);
            }
            if !self.search_term.is_empty() {
                let term = self.search_term.to_lowercase();
                filtered.retain(|u| match self.search_field.as_str() {
                    "User ID" => u.id.to_lowercase().contains(&term),
                    "Email" => u.email.to_lowercase().contains(&term),
                    "Display Name" => u.display_name.to_lowercase().contains(&term),
                    "First Name" => Self::get_attribute_value(u, "firstname").unwrap_or_default().to_lowercase().contains(&term),
                    "Last Name" => Self::get_attribute_value(u, "lastname").unwrap_or_default().to_lowercase().contains(&term),
                    _ => true,
                });
            }
            filtered
        });

        let all_selected = !filtered_users.is_empty() &&
        filtered_users.iter().all(|u| self.selected_users.contains(&u.id));

        html! {
            <div class="table-responsive">
            <table class="table table-hover">
            <thead>
            <tr>
            <th>
            <input type="checkbox" checked={all_selected}
            onclick={ctx.link().callback(|_| Msg::ToggleSelectAll)} />
            </th>
            <th class="fw-bold fs-8">{"User ID"}</th>
            <th class="fw-bold fs-8">{"OU"}</th>
            <th class="fw-bold fs-8">{"Email"}</th>
            <th class="fw-bold fs-8">{"Display name"}</th>
            <th class="fw-bold fs-8">{"First name"}</th>
            <th class="fw-bold fs-8">{"Last name"}</th>
            <th class="fw-bold fs-8">{"Creation date"}</th>
            <th class="fw-bold fs-8">{"Kerberos Sync"}</th>
            </tr>
            </thead>
            <tbody>
            {for filtered_users.iter().map(|u| self.view_user(ctx, u))}
            </tbody>
            </table>
            </div>
        }
    }

    fn view_user(&self, ctx: &Context<Self>, user: &User) -> Html {
        let first_name = Self::get_attribute_value(user, "firstname").unwrap_or_default();
        let last_name = Self::get_attribute_value(user, "lastname").unwrap_or_default();
        let kerberos_sync = Self::get_kerberos_sync(user);
        let ou = Self::get_ou(user);
        let is_selected = self.selected_users.contains(&user.id);
        let user_id = user.id.clone();

        html! {
            <tr key={user.id.clone()}>
            <td>
            <input type="checkbox" checked={is_selected}
            onclick={ctx.link().callback(move |_| Msg::ToggleUserSelection(user_id.clone()))} />
            </td>
            <td><Link to={AppRoute::UserDetails{user_id: user.id.clone()}}>{&user.id}</Link></td>
            <td>{ou}</td>
            <td>{&user.email}</td>
            <td>{&user.display_name}</td>
            <td>{first_name}</td>
            <td>{last_name}</td>
            <td>{user.creation_date.naive_local().date()}</td>
            <td>
            {if kerberos_sync {
                render_check()
            } else {
                html! { <span class="text-muted">{"–"}</span> }
            }}
            </td>
            </tr>
        }
    }

    fn view_errors(&self) -> Html {
        match &self.common.error {
            None => html! {},
            Some(e) => html! {<div class="alert alert-danger">{"Error: "}{e.to_string()}</div>},
        }
    }
}

fn render_check() -> Html {
    html! {
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-check" viewBox="0 0 16 16">
        <path d="M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425z"></path>
        </svg>
    }
}
