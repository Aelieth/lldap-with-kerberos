use crate::{
    components::{
        delete_user::DeleteUser,
        router::{AppRoute, Link},
    },
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use list_users_query::ResponseData;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "queries/list_users.graphql",
response_derives = "Debug",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListUsersQuery;

type User = list_users_query::ListUsersQueryUsers;

pub struct UserTable {
    common: CommonComponentParts<Self>,
    users: Option<Vec<User>>,
}

pub enum Msg {
    ListUsersResponse(Result<ResponseData>),
    OnUserDeleted(String),
    OnError(Error),
}

impl CommonComponent<UserTable> for UserTable {
    fn handle_msg(&mut self, _: &Context<Self>, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::ListUsersResponse(users) => {
                self.users = Some(users?.users.into_iter().collect());
                Ok(true)
            }
            Msg::OnError(e) => Err(e),
            Msg::OnUserDeleted(user_id) => {
                if let Some(users) = &mut self.users {
                    users.retain(|u| u.id != user_id);
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
        .and_then(|a| a.value.first().cloned())  // ← take first element (singleton)
    }
}

impl Component for UserTable {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = UserTable {
            common: CommonComponentParts::<Self>::create(),
            users: None,
        };
        table.common.call_graphql::<ListUsersQuery, _>(
            ctx,
            list_users_query::Variables { filters: None },
            Msg::ListUsersResponse,
            "Error trying to fetch users",
        );
        table
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div>
            {self.view_users(ctx)}
            {self.view_errors()}
            </div>
        }
    }
}

impl UserTable {
    fn view_users(&self, ctx: &Context<Self>) -> Html {
        let make_table = |users: &Vec<User>| {
            html! {
                <div class="table-responsive">
                <table class="table table-hover">
                <thead>
                <tr>
                <th>{"User ID"}</th>
                <th>{"Email"}</th>
                <th>{"Display name"}</th>
                <th>{"First name"}</th>
                <th>{"Last name"}</th>
                <th>{"Creation date"}</th>
                <th>{"Kerberos Sync"}</th>
                <th>{"Delete"}</th>
                </tr>
                </thead>
                <tbody>
                {users.iter().map(|u| self.view_user(ctx, u)).collect::<Vec<_>>()}
                </tbody>
                </table>
                </div>
            }
        };
        match &self.users {
            None => html! {{"Loading..."}},
            Some(users) => make_table(users),
        }
    }

    fn view_user(&self, ctx: &Context<Self>, user: &User) -> Html {
        let first_name = Self::get_attribute_value(user, "firstname").unwrap_or_default();
        let last_name = Self::get_attribute_value(user, "lastname").unwrap_or_default();
        let kerberos_sync = Self::get_attribute_value(user, "kerberossync").map_or(false, |v| v == "1");

        html! {
            <tr key={user.id.clone()}>
            <td><Link to={AppRoute::UserDetails{user_id: user.id.clone()}}>{&user.id}</Link></td>
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
            <td>
            <DeleteUser
            username={user.id.clone()}
            on_user_deleted={ctx.link().callback(Msg::OnUserDeleted)}
            on_error={ctx.link().callback(Msg::OnError)}/>
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
