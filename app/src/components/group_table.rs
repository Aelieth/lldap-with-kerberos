use crate::{
    components::{
        router::{AppRoute, Link},
        ou_table::OuTable,
        change_group_ou::ChangeGroupOu,
        delete_group::DeleteGroup,
    },
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use list_user_ous_query::ResponseData as OusResponseData;
use yew::prelude::*;
use wasm_bindgen::JsCast;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_group_list.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetGroupList;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_user_ous.graphql",
    response_derives = "Debug, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListUserOusQuery;

use get_group_list::ResponseData;

pub type Group = get_group_list::GetGroupListGroups;

pub struct GroupTable {
    common: CommonComponentParts<Self>,
    groups: Option<Vec<Group>>,
    ou_filter: String,
    search_term: String,
    search_field: String,
    ous: Vec<String>,
    selected_groups: Vec<i64>,
}

pub enum Msg {
    ListGroupsResponse(Result<ResponseData>),
    ListUserOusResponse(Result<OusResponseData>),
    OnGroupDeleted(i64),
    OnError(Error),
    OuFilterChanged(String),
    SearchTermChanged(String),
    SearchFieldChanged(String),
    ToggleGroupSelection(i64),
    ToggleSelectAll,
    OuCreated(String),
    OuDeleted(String),
    ChangeOuForSelected(String),
}

impl CommonComponent<GroupTable> for GroupTable {
    fn handle_msg(&mut self, ctx: &Context<Self>, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::ListGroupsResponse(groups) => {
                self.groups = Some(groups?.groups.into_iter().collect());
                Ok(true)
            }
            Msg::ListUserOusResponse(ous) => {
                self.ous = ous?.user_ous;
                Ok(true)
            }
            Msg::OnError(e) => Err(e),
            Msg::OnGroupDeleted(group_id) => {
                if let Some(groups) = &mut self.groups {
                    groups.retain(|g| g.id != group_id);
                }
                self.selected_groups.retain(|id| *id != group_id);
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
            Msg::ToggleGroupSelection(group_id) => {
                if self.selected_groups.contains(&group_id) {
                    self.selected_groups.retain(|id| *id != group_id);
                } else {
                    self.selected_groups.push(group_id);
                }
                Ok(true)
            }
            Msg::ToggleSelectAll => {
                if let Some(groups) = &self.groups {
                    let mut filtered = groups.clone();
                    if self.ou_filter != "All" {
                        filtered.retain(|g| Self::get_ou(g) == self.ou_filter);
                    }
                    if !self.search_term.is_empty() {
                        let term = self.search_term.to_lowercase();
                        filtered.retain(|g| match self.search_field.as_str() {
                            "Group Name" => g.display_name.to_lowercase().contains(&term),
                            "OU" => Self::get_ou(g).to_lowercase().contains(&term),
                            _ => true,
                        });
                    }
                    let filtered_ids: Vec<i64> = filtered.iter().map(|g| g.id).collect();
                    if self.selected_groups.len() == filtered_ids.len() && !filtered_ids.is_empty() {
                        self.selected_groups.clear();
                    } else {
                        self.selected_groups = filtered_ids;
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
            Msg::ChangeOuForSelected(_new_ou) => {
                self.selected_groups.clear();
                self.common.call_graphql::<GetGroupList, _>(
                    ctx,
                    get_group_list::Variables {},
                    Msg::ListGroupsResponse,
                    "Error trying to fetch groups after OU change",
                );
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl GroupTable {
    fn get_attribute_value(group: &Group, name: &str) -> Option<String> {
        group.attributes
            .iter()
            .find(|a| a.name == name)
            .and_then(|a| a.value.first().cloned())
    }

    fn get_ou(group: &Group) -> String {
        Self::get_attribute_value(group, "ou").unwrap_or_else(|| "groups".to_string())
    }
}

impl Component for GroupTable {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = GroupTable {
            common: CommonComponentParts::<Self>::create(),
            groups: None,
            ou_filter: "All".to_string(),
            search_term: String::new(),
            search_field: "Group Name".to_string(),
            ous: vec![],
            selected_groups: Vec::new(),
        };

        table.common.call_graphql::<GetGroupList, _>(
            ctx,
            get_group_list::Variables {},
            Msg::ListGroupsResponse,
            "Error trying to fetch groups",
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
            <OuTable
            ou_filter={self.ou_filter.clone()}
            ous={self.ous.clone()}
            on_ou_changed={ctx.link().callback(Msg::OuFilterChanged)}
            on_ou_created={ctx.link().callback(Msg::OuCreated)}
            on_ou_deleted={ctx.link().callback(Msg::OuDeleted)}
            error={self.common.error.as_ref().map(|e| e.to_string())}
            default_primary={"groups".to_string()}
            />
            <hr class="my-4" />

            <div class="row g-3 align-items-end mb-3">
                <div class="col-auto">
                    <Link classes="btn btn-primary" to={AppRoute::CreateGroup}>
                        <i class="bi-people-fill me-2"></i>
                        {"Create Group"}
                    </Link>
                </div>
                <div class="col-auto">
                    <ChangeGroupOu
                        selected_groups={self.selected_groups.clone()}
                        ous={self.ous.clone()}
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
                        { for vec!["Group Name".to_string(), "OU".to_string()].iter().map(|f| html! {
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

            {self.view_groups(ctx)}

            <div class="row justify-content-start mt-3">
                <div class="col-auto">
                    // Bulk delete can be added later (next turtle step)
                </div>
            </div>

            {self.view_errors()}
            </div>
        }
    }
}

impl GroupTable {
    fn view_groups(&self, ctx: &Context<Self>) -> Html {
        let filtered_groups = self.groups.as_ref().map_or(vec![], |groups| {
            let mut filtered = groups.clone();
            if self.ou_filter != "All" {
                filtered.retain(|g| Self::get_ou(g) == self.ou_filter);
            }
            if !self.search_term.is_empty() {
                let term = self.search_term.to_lowercase();
                filtered.retain(|g| match self.search_field.as_str() {
                    "Group Name" => g.display_name.to_lowercase().contains(&term),
                    "OU" => Self::get_ou(g).to_lowercase().contains(&term),
                    _ => true,
                });
            }
            filtered
        });

        let all_selected = !filtered_groups.is_empty() &&
            filtered_groups.iter().all(|g| self.selected_groups.contains(&g.id));

        html! {
            <div class="table-responsive">
            <table class="table table-hover">
            <thead>
            <tr>
            <th>
            <input type="checkbox" checked={all_selected}
            onclick={ctx.link().callback(|_| Msg::ToggleSelectAll)} />
            </th>
            <th class="fw-bold fs-8">{"Group name"}</th>
            <th class="fw-bold fs-8">{"OU"}</th>
            <th class="fw-bold fs-8">{"Creation date"}</th>
            <th class="fw-bold fs-8">{"Delete"}</th>
            </tr>
            </thead>
            <tbody>
            {for filtered_groups.iter().map(|g| self.view_group(ctx, g))}
            </tbody>
            </table>
            </div>
        }
    }

    fn view_group(&self, ctx: &Context<Self>, group: &Group) -> Html {
        let is_selected = self.selected_groups.contains(&group.id);
        let group_id = group.id;

        html! {
            <tr key={group.id}>
            <td>
            <input type="checkbox" checked={is_selected}
            onclick={ctx.link().callback(move |_| Msg::ToggleGroupSelection(group_id))} />
            </td>
            <td><Link to={AppRoute::GroupDetails{group_id: group.id}}>{&group.display_name}</Link></td>
            <td>{Self::get_ou(group)}</td>
            <td>{group.creation_date.naive_local().date()}</td>
            <td>
                <DeleteGroup
                    group={group.clone()}
                    on_group_deleted={ctx.link().callback(Msg::OnGroupDeleted)}
                    on_error={ctx.link().callback(Msg::OnError)}
                />
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
