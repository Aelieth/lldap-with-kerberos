// crates/graphql-server/src/components/posix_options.rs
use crate::{
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::Result;
use graphql_client::GraphQLQuery;
use yew::prelude::*;
use wasm_bindgen::JsCast;

// GraphQL derives (kept inside the component file so POSIX stays 100% self-contained)
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_posix_config.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetPosixConfig;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/set_posix_config.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct SetPosixConfig;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/reassign_gid_numbers.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReassignGidNumbers;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/reassign_user_uid_numbers.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReassignUserUidNumbers;

#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "queries/reassign_user_gid_numbers.graphql",
response_derives = "Debug",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReassignUserGidNumbers;

#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "queries/reassign_user_homedirectories.graphql",
response_derives = "Debug",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReassignUserHomeDirectories;

#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "queries/reassign_user_loginshells.graphql",
response_derives = "Debug",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReassignUserLoginShells;

#[derive(Properties, PartialEq)]
pub struct PosixOptionsProps {
    pub on_status_update: Callback<String>,
}

pub struct PosixOptions {
    common: CommonComponentParts<Self>,
    // Full PosixSettings from backend
    user_uidnumber_assign: bool,
    user_uidnumber_start: String,
    user_uidnumber_max: String,
    user_gidnumber_assign: bool,
    user_gidnumber_start: String,
    user_loginshell_assign: bool,
    user_loginshell_default: String,
    user_homedirectory_assign: bool,
    user_homedirectory_prefix: String,

    group_gidnumber_assign: bool,
    group_gidnumber_start: String,
    group_gidnumber_max: String,
    ranges_changed: bool,
    config_changed: bool,
    loading: bool,
}

pub enum Msg {
    LoadConfig,
    ConfigResponse(Result<get_posix_config::ResponseData>),
    UpdateUserUidAssign(bool),
    UpdateUserUidStart(String),
    UpdateUserUidMax(String),
    UpdateUserGidAssign(bool),
    UpdateUserGidStart(String),
    UpdateUserLoginShellAssign(bool),
    UpdateUserLoginShellDefault(String),
    UpdateUserHomeAssign(bool),
    UpdateUserHomePrefix(String),
    UpdateGroupGidAssign(bool),
    UpdateGroupGidStart(String),
    UpdateGroupGidMax(String),
    SaveConfig,
    SaveResponse(Result<set_posix_config::ResponseData>),
    ReassignUserUidNumbers,
    ReassignUserGidNumbers,
    ReassignUserLoginShells,
    ReassignUserHomeDirectories,
    ReassignGroupGidNumbers,
    ReassignResponse(Result<reassign_gid_numbers::ResponseData>),
}

impl CommonComponent<PosixOptions> for PosixOptions {
    fn handle_msg(&mut self, ctx: &Context<Self>, msg: Self::Message) -> Result<bool> {
        match msg {
            Msg::LoadConfig => {
                let vars = get_posix_config::Variables {};
                self.common.call_graphql::<GetPosixConfig, _>(
                    ctx, vars, Msg::ConfigResponse, "Failed to load POSIX config",
                );
                self.loading = true;
                Ok(false)
            }
            Msg::ConfigResponse(Ok(data)) => {
                let cfg = data.posix_settings;
                self.user_uidnumber_assign = cfg.user_uidnumber_assign;
                self.user_uidnumber_start = cfg.user_uidnumber_start.to_string();
                self.user_uidnumber_max = cfg.user_uidnumber_max.to_string();
                self.user_gidnumber_assign = cfg.user_gidnumber_assign;
                self.user_gidnumber_start = cfg.user_gidnumber_start.to_string();
                self.user_loginshell_assign = cfg.user_loginshell_assign;
                self.user_loginshell_default = cfg.user_loginshell_default;
                self.user_homedirectory_assign = cfg.user_homedirectory_assign;
                self.user_homedirectory_prefix = cfg.user_homedirectory_prefix;
                self.group_gidnumber_assign = cfg.group_gidnumber_assign;
                self.group_gidnumber_start = cfg.group_gidnumber_start.to_string();
                self.group_gidnumber_max = cfg.group_gidnumber_max.to_string();

                self.loading = false;
                self.config_changed = false;
                ctx.props().on_status_update.emit("✅ POSIX config loaded successfully".to_string());
                Ok(true)
            }
            Msg::ConfigResponse(Err(e)) => {
                self.loading = false;
                ctx.props().on_status_update.emit(format!("❌ Failed to load POSIX config: {}", e));
                Ok(true)
            }
            Msg::UpdateUserUidAssign(v) => { self.user_uidnumber_assign = v; self.config_changed = true; Ok(true) }
            Msg::UpdateUserUidStart(s) => { self.user_uidnumber_start = s; self.config_changed = true; Ok(true) }
            Msg::UpdateUserUidMax(s) => { self.user_uidnumber_max = s; self.config_changed = true; Ok(true) }
            Msg::UpdateUserGidAssign(v) => { self.user_gidnumber_assign = v; self.config_changed = true; Ok(true) }
            Msg::UpdateUserGidStart(s) => { self.user_gidnumber_start = s; self.config_changed = true; Ok(true) }
            Msg::UpdateUserLoginShellAssign(v) => { self.user_loginshell_assign = v; self.config_changed = true; Ok(true) }
            Msg::UpdateUserLoginShellDefault(s) => { self.user_loginshell_default = s; self.config_changed = true; Ok(true) }
            Msg::UpdateUserHomeAssign(v) => { self.user_homedirectory_assign = v; self.config_changed = true; Ok(true) }
            Msg::UpdateUserHomePrefix(s) => { self.user_homedirectory_prefix = s; self.config_changed = true; Ok(true) }
            Msg::UpdateGroupGidAssign(v) => { self.group_gidnumber_assign = v; self.config_changed = true; Ok(true) }
            Msg::UpdateGroupGidStart(s) => { self.group_gidnumber_start = s; self.config_changed = true; Ok(true) }
            Msg::UpdateGroupGidMax(s) => { self.group_gidnumber_max = s; self.config_changed = true; Ok(true) }

            Msg::SaveConfig => {
                let input = set_posix_config::PosixSettingsInput {
                    userUidnumberAssign: self.user_uidnumber_assign,
                    userUidnumberStart: self.user_uidnumber_start.parse().unwrap_or(3001),
                    userUidnumberMax: self.user_uidnumber_max.parse().unwrap_or(3999),
                    userGidnumberAssign: self.user_gidnumber_assign,
                    userGidnumberStart: self.user_gidnumber_start.parse().unwrap_or(3001),
                    userLoginshellAssign: self.user_loginshell_assign,
                    userLoginshellDefault: self.user_loginshell_default.clone(),
                    userHomedirectoryAssign: self.user_homedirectory_assign,
                    userHomedirectoryPrefix: self.user_homedirectory_prefix.clone(),
                    groupGidnumberAssign: self.group_gidnumber_assign,
                    groupGidnumberStart: self.group_gidnumber_start.parse().unwrap_or(3001),
                    groupGidnumberMax: self.group_gidnumber_max.parse().unwrap_or(3999),
                };
                let vars = set_posix_config::Variables { input };
                self.common.call_graphql::<SetPosixConfig, _>(
                    ctx, vars, Msg::SaveResponse, "Failed to save POSIX config",
                );
                Ok(false)
            }
            Msg::SaveResponse(Ok(_)) => {
                self.config_changed = false;
                ctx.props().on_status_update.emit("✅ POSIX config saved successfully".to_string());
                Ok(true)
            }
            Msg::SaveResponse(Err(e)) => {
                ctx.props().on_status_update.emit(format!("❌ Failed to save POSIX config: {}", e));
                Ok(true)
            }

            // Reassign actions - using closures to fix type mismatch
            Msg::ReassignUserUidNumbers => {
                let vars = reassign_user_uid_numbers::Variables {};
                self.common.call_graphql::<ReassignUserUidNumbers, _>(
                    ctx, vars, |r| Msg::ReassignResponse(r), "Failed to reassign user uidNumbers",
                );
                Ok(false)
            }
            Msg::ReassignUserGidNumbers => {
                let vars = reassign_user_gid_numbers::Variables {};
                self.common.call_graphql::<ReassignUserGidNumbers, _>(
                    ctx, vars, |r| Msg::ReassignResponse(r), "Failed to reassign user gidNumbers",
                );
                Ok(false)
            }
            Msg::ReassignUserLoginShells => {
                let vars = reassign_user_loginshells::Variables {};
                self.common.call_graphql::<ReassignUserLoginShells, _>(
                    ctx, vars, |r| Msg::ReassignResponse(r), "Failed to reassign user loginShells",
                );
                Ok(false)
            }
            Msg::ReassignUserHomeDirectories => {
                let vars = reassign_user_homedirectories::Variables {};
                self.common.call_graphql::<ReassignUserHomeDirectories, _>(
                    ctx, vars, |r| Msg::ReassignResponse(r), "Failed to reassign user homeDirectories",
                );
                Ok(false)
            }
            Msg::ReassignGroupGidNumbers => {
                let vars = reassign_gid_numbers::Variables {};
                self.common.call_graphql::<ReassignGidNumbers, _>(
                    ctx, vars, |r| Msg::ReassignResponse(r), "Failed to reassign group gidNumbers",
                );
                Ok(false)
            }

            // Shared response handler
            Msg::ReassignResponse(Ok(_)) => {
                ctx.props().on_status_update.emit("✅ Reassign completed successfully".to_string());
                Ok(true)
            }
            Msg::ReassignResponse(Err(e)) => {
                ctx.props().on_status_update.emit(format!("❌ Reassign failed: {}", e));
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> { &mut self.common }
}

impl Component for PosixOptions {
    type Message = Msg;
    type Properties = PosixOptionsProps;

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Msg::LoadConfig);
        Self {
            common: CommonComponentParts::<Self>::create(),
            user_uidnumber_assign: false,
            user_uidnumber_start: "3001".to_string(),
            user_uidnumber_max: "3999".to_string(),
            user_gidnumber_assign: false,
            user_gidnumber_start: "3001".to_string(),
            user_loginshell_assign: false,
            user_loginshell_default: "/bin/bash".to_string(),
            user_homedirectory_assign: false,
            user_homedirectory_prefix: "/home".to_string(),
            group_gidnumber_assign: false,
            group_gidnumber_start: "3001".to_string(),
            group_gidnumber_max: "3999".to_string(),
            ranges_changed: false,
            config_changed: false,
            loading: true,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.handle_msg(ctx, msg).unwrap_or(false)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

        // Toggle & input callbacks
        let on_user_uid_assign = link.callback(|e: Event| {
            let checked = e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().checked();
            Msg::UpdateUserUidAssign(checked)
        });
        let on_user_uid_start = link.callback(|e: InputEvent| Msg::UpdateUserUidStart(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_user_uid_max = link.callback(|e: InputEvent| Msg::UpdateUserUidMax(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_user_gid_assign = link.callback(|e: Event| {
            let checked = e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().checked();
            Msg::UpdateUserGidAssign(checked)
        });
        let on_user_gid_start = link.callback(|e: InputEvent| Msg::UpdateUserGidStart(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_user_loginshell_assign = link.callback(|e: Event| {
            let checked = e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().checked();
            Msg::UpdateUserLoginShellAssign(checked)
        });
        let on_user_loginshell_default = link.callback(|e: InputEvent| Msg::UpdateUserLoginShellDefault(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_user_home_assign = link.callback(|e: Event| {
            let checked = e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().checked();
            Msg::UpdateUserHomeAssign(checked)
        });
        let on_user_home_prefix = link.callback(|e: InputEvent| Msg::UpdateUserHomePrefix(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_group_gid_assign = link.callback(|e: Event| {
            let checked = e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().checked();
            Msg::UpdateGroupGidAssign(checked)
        });
        let on_group_gid_start = link.callback(|e: InputEvent| Msg::UpdateGroupGidStart(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_group_gid_max = link.callback(|e: InputEvent| Msg::UpdateGroupGidMax(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));

        // Reassign callbacks
        let on_reassign_user_uid = link.callback(|_| Msg::ReassignUserUidNumbers);
        let on_reassign_user_gid = link.callback(|_| Msg::ReassignUserGidNumbers);
        let on_reassign_user_loginshell = link.callback(|_| Msg::ReassignUserLoginShells);
        let on_reassign_user_home = link.callback(|_| Msg::ReassignUserHomeDirectories);
        let on_reassign_group_gid = link.callback(|_| Msg::ReassignGroupGidNumbers);

        let on_save = link.callback(|_| Msg::SaveConfig);

        let save_disabled = self.loading || !self.config_changed;
        let reassign_disabled = !self.config_changed || self.loading;

        html! {
            <div class="row">
                <div class="col-12">
                    <div class="card mb-4">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5>{ "POSIX Attributes" }</h5>
                            <span class="badge bg-info">{ "Status: POSIX config loaded successfully" }</span>
                        </div>
                        <div class="card-body">

                            // USERS SECTION
                            <h6 class="text-muted mb-3">{ "USERS SECTION" }</h6>
                            <div class="mb-4">
                                <div class="d-flex align-items-center mb-3">
                                    <div class="form-check flex-grow-1">
                                        <input type="checkbox" class="form-check-input" checked={self.user_uidnumber_assign} onchange={on_user_uid_assign} disabled={self.loading} />
                                        <label class="form-check-label">{ "Auto-assign uidNumber range:" }</label>
                                    </div>
                                    <input type="number" class="form-control form-control-sm mx-2" style="width: 90px;" value={self.user_uidnumber_start.clone()} oninput={on_user_uid_start} min="1000" disabled={self.loading} />
                                    <span class="mx-1 text-muted small">{ "to" }</span>
                                    <input type="number" class="form-control form-control-sm mx-2" style="width: 90px;" value={self.user_uidnumber_max.clone()} oninput={on_user_uid_max} min="1000" disabled={self.loading} />
                                    <button onclick={on_reassign_user_uid} class="btn btn-warning btn-sm ms-2" disabled={reassign_disabled}>{ "Reassign" }</button>
                                </div>

                                <div class="d-flex align-items-center mb-3">
                                    <div class="form-check flex-grow-1">
                                        <input type="checkbox" class="form-check-input" checked={self.user_gidnumber_assign} onchange={on_user_gid_assign} disabled={self.loading} />
                                        <label class="form-check-label">{ "Auto-assign gidNumber:" }</label>
                                    </div>
                                    <input type="number" class="form-control form-control-sm mx-2" style="width: 120px;" value={self.user_gidnumber_start.clone()} oninput={on_user_gid_start} min="1000" disabled={self.loading} />
                                    <button onclick={on_reassign_user_gid} class="btn btn-warning btn-sm ms-2" disabled={reassign_disabled}>{ "Reassign" }</button>
                                </div>

                                <div class="d-flex align-items-center mb-3">
                                    <div class="form-check flex-grow-1">
                                        <input type="checkbox" class="form-check-input" checked={self.user_loginshell_assign} onchange={on_user_loginshell_assign} disabled={self.loading} />
                                        <label class="form-check-label">{ "Auto-assign loginShell:" }</label>
                                    </div>
                                    <input type="text" class="form-control form-control-sm mx-2" style="width: 160px;" value={self.user_loginshell_default.clone()} oninput={on_user_loginshell_default} disabled={self.loading} />
                                    <button onclick={on_reassign_user_loginshell} class="btn btn-warning btn-sm ms-2" disabled={reassign_disabled}>{ "Reassign" }</button>
                                </div>

                                <div class="d-flex align-items-center mb-3">
                                    <div class="form-check flex-grow-1">
                                        <input type="checkbox" class="form-check-input" checked={self.user_homedirectory_assign} onchange={on_user_home_assign} disabled={self.loading} />
                                        <label class="form-check-label">{ "Auto-assign homeDirectory:" }</label>
                                    </div>
                                    <input type="text" class="form-control form-control-sm mx-2" style="width: 160px;" value={self.user_homedirectory_prefix.clone()} oninput={on_user_home_prefix} disabled={self.loading} />
                                    <button onclick={on_reassign_user_home} class="btn btn-warning btn-sm ms-2" disabled={reassign_disabled}>{ "Reassign" }</button>
                                </div>
                            </div>

                            // GROUPS SECTION
                            <h6 class="text-muted mb-3">{ "GROUPS SECTION" }</h6>
                            <div class="mb-4">
                                <div class="d-flex align-items-center">
                                    <div class="form-check flex-grow-1">
                                        <input type="checkbox" class="form-check-input" checked={self.group_gidnumber_assign} onchange={on_group_gid_assign} disabled={self.loading} />
                                        <label class="form-check-label">{ "Auto-assign gidNumber range:" }</label>
                                    </div>
                                    <input type="number" class="form-control form-control-sm mx-2" style="width: 90px;" value={self.group_gidnumber_start.clone()} oninput={on_group_gid_start} min="1000" disabled={self.loading} />
                                    <span class="mx-1 text-muted small">{ "to" }</span>
                                    <input type="number" class="form-control form-control-sm mx-2" style="width: 90px;" value={self.group_gidnumber_max.clone()} oninput={on_group_gid_max} min="1000" disabled={self.loading} />
                                    <button onclick={on_reassign_group_gid} class="btn btn-warning btn-sm ms-2" disabled={reassign_disabled}>{ "Reassign" }</button>
                                </div>
                            </div>

                        </div>

                        // Save button right-aligned with breathing room
                        <div class="card-footer text-end pe-3">
                            <button onclick={on_save} class="btn btn-success px-4" disabled={save_disabled}>
                                { "Save POSIX Config" }
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}
