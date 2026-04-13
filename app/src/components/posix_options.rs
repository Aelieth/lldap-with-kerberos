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
    query_path = "queries/reassign_uid_numbers.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ReassignUidNumbers;

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
    ReassignGidNumbers,
    ReassignUidNumbers,
    ReassignGidResponse(Result<reassign_gid_numbers::ResponseData>),
    ReassignUidResponse(Result<reassign_uid_numbers::ResponseData>),
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
            Msg::ReassignGidNumbers => {
                let vars = reassign_gid_numbers::Variables {};
                self.common.call_graphql::<ReassignGidNumbers, _>(
                    ctx, vars, Msg::ReassignGidResponse, "Failed to reassign gidNumbers",
                );
                Ok(false)
            }
            Msg::ReassignUidNumbers => {
                let vars = reassign_uid_numbers::Variables {};
                self.common.call_graphql::<ReassignUidNumbers, _>(
                    ctx, vars, Msg::ReassignUidResponse, "Failed to reassign uidNumbers",
                );
                Ok(false)
            }
            Msg::ReassignGidResponse(Ok(_)) => {
                ctx.props().on_status_update.emit("✅ All group gidNumbers reassigned successfully".to_string());
                Ok(true)
            }
            Msg::ReassignGidResponse(Err(e)) => {
                ctx.props().on_status_update.emit(format!("❌ Reassign gidNumbers failed: {}", e));
                Ok(true)
            }
            Msg::ReassignUidResponse(Ok(_)) => {
                ctx.props().on_status_update.emit("✅ All user uidNumbers reassigned successfully".to_string());
                Ok(true)
            }
            Msg::ReassignUidResponse(Err(e)) => {
                ctx.props().on_status_update.emit(format!("❌ Reassign uidNumbers failed: {}", e));
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
            config_changed: false,
            loading: true,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.handle_msg(ctx, msg).unwrap_or(false)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

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

        let on_save = link.callback(|_| Msg::SaveConfig);
        let on_reassign_uid = link.callback(|_| Msg::ReassignUidNumbers);
        let on_reassign_gid = link.callback(|_| Msg::ReassignGidNumbers);

        let save_disabled = self.loading || !self.config_changed;
        let reassign_disabled = !self.config_changed || self.loading;

        html! {
            <div class="row">
                <div class="col-12">
                    <div class="card mb-4">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5>{ "POSIX Attributes" }</h5>
                            <span class="badge bg-info">{ "Status: POSIX config loaded successfully" }</span>  // parent alert handles real status
                        </div>
                        <div class="card-body">

                            // USERS SECTION
                            <h6 class="text-muted mb-3">{ "USERS SECTION" }</h6>
                            <div class="mb-4">
                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" checked={self.user_uidnumber_assign} onchange={on_user_uid_assign} disabled={self.loading} />
                                    <label class="form-check-label">{ "Auto-assign uidNumber to new users" }</label>
                                </div>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label">{"Starting uidNumber"}</label>
                                        <input type="number" class="form-control" value={self.user_uidnumber_start.clone()} oninput={on_user_uid_start} min="1000" disabled={self.loading} />
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">{"Maximum"}</label>
                                        <input type="number" class="form-control" value={self.user_uidnumber_max.clone()} oninput={on_user_uid_max} min="1000" disabled={self.loading} />
                                    </div>
                                </div>

                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" checked={self.user_gidnumber_assign} onchange={on_user_gid_assign} disabled={self.loading} />
                                    <label class="form-check-label">{ "Auto-assign gidNumber to new users" }</label>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">{"Starting gidNumber"}</label>
                                    <input type="number" class="form-control" value={self.user_gidnumber_start.clone()} oninput={on_user_gid_start} min="1000" disabled={self.loading} />
                                </div>

                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" checked={self.user_loginshell_assign} onchange={on_user_loginshell_assign} disabled={self.loading} />
                                    <label class="form-check-label">{ "Auto-assign loginShell" }</label>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">{"Default loginShell"}</label>
                                    <input type="text" class="form-control" value={self.user_loginshell_default.clone()} oninput={on_user_loginshell_default} disabled={self.loading} />
                                </div>

                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" checked={self.user_homedirectory_assign} onchange={on_user_home_assign} disabled={self.loading} />
                                    <label class="form-check-label">{ "Auto-assign homeDirectory" }</label>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">{"Home prefix"}</label>
                                    <input type="text" class="form-control" value={self.user_homedirectory_prefix.clone()} oninput={on_user_home_prefix} disabled={self.loading} />
                                </div>
                            </div>

                            // GROUPS SECTION
                            <h6 class="text-muted mb-3">{ "GROUPS SECTION" }</h6>
                            <div class="mb-4">
                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" checked={self.group_gidnumber_assign} onchange={on_group_gid_assign} disabled={self.loading} />
                                    <label class="form-check-label">{ "Auto-assign gidNumber to new groups" }</label>
                                </div>
                                <div class="row g-3">
                                    <div class="col-md-6">
                                        <label class="form-label">{"Starting gidNumber"}</label>
                                        <input type="number" class="form-control" value={self.group_gidnumber_start.clone()} oninput={on_group_gid_start} min="1000" disabled={self.loading} />
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">{"Maximum"}</label>
                                        <input type="number" class="form-control" value={self.group_gidnumber_max.clone()} oninput={on_group_gid_max} min="1000" disabled={self.loading} />
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="card-footer d-flex gap-2">
                            <button onclick={on_save} class="btn btn-success flex-fill" disabled={save_disabled}>
                                { "Save POSIX Config" }
                            </button>
                            <button onclick={on_reassign_uid} class="btn btn-warning flex-fill" disabled={reassign_disabled}>
                                { "Reassign uidNumbers" }
                            </button>
                            <button onclick={on_reassign_gid} class="btn btn-warning flex-fill" disabled={reassign_disabled}>
                                { "Reassign gidNumbers" }
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}
