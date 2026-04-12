use crate::{
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::Result;
use graphql_client::GraphQLQuery;
use yew::prelude::*;
use wasm_bindgen::JsCast;   // ← REQUIRED for .dyn_into on EventTarget

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

#[derive(Properties, PartialEq)]
pub struct PosixOptionsProps {
    pub on_status_update: Callback<String>,
}

pub struct PosixOptions {
    common: CommonComponentParts<Self>,
    auto_gid_enabled: bool,
    gid_start: String,
    config_changed: bool,
    loading: bool,
}

pub enum Msg {
    LoadConfig,
    ConfigResponse(Result<get_posix_config::ResponseData>),
    UpdateAutoGid(bool),
    UpdateGidStart(String),
    SaveConfig,
    SaveResponse(Result<set_posix_config::ResponseData>),
    ReassignGidNumbers,
    ReassignResponse(Result<reassign_gid_numbers::ResponseData>),
}

impl CommonComponent<PosixOptions> for PosixOptions {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::LoadConfig => {
                let vars = get_posix_config::Variables {};
                self.common.call_graphql::<GetPosixConfig, _>(
                    ctx,
                    vars,
                    Msg::ConfigResponse,
                    "Failed to load POSIX config",
                );
                Ok(false)
            }
            Msg::ConfigResponse(Ok(data)) => {
                let cfg = data.posix_config;
                self.auto_gid_enabled = cfg.auto_gid_enabled;
                self.gid_start = cfg.gid_start.to_string();
                self.loading = false;
                ctx.props().on_status_update.emit("POSIX config loaded".to_string());
                Ok(true)
            }
            Msg::ConfigResponse(Err(e)) => {
                ctx.props().on_status_update.emit(format!("❌ Failed to load POSIX config: {}", e));
                self.loading = false;
                Ok(true)
            }
            Msg::UpdateAutoGid(v) => {
                self.auto_gid_enabled = v;
                self.config_changed = true;
                Ok(true)
            }
            Msg::UpdateGidStart(s) => {
                self.gid_start = s;
                self.config_changed = true;
                Ok(true)
            }
            Msg::SaveConfig => {
                let input = set_posix_config::PosixConfigInput {
                    autoGidEnabled: self.auto_gid_enabled,
                    gidStart: self.gid_start.parse().unwrap_or(3001),
                };
                let vars = set_posix_config::Variables { input };
                self.common.call_graphql::<SetPosixConfig, _>(
                    ctx,
                    vars,
                    Msg::SaveResponse,
                    "Failed to save POSIX config",
                );
                Ok(false)
            }
            Msg::SaveResponse(Ok(data)) => {
                let resp = data.set_posix_config;
                ctx.props().on_status_update.emit(if resp.success {
                    "✅ POSIX config saved successfully".to_string()
                } else {
                    format!("❌ {}", resp.message)
                });
                self.config_changed = false;
                Ok(true)
            }
            Msg::SaveResponse(Err(e)) => {
                ctx.props().on_status_update.emit(format!("❌ Failed to save POSIX config: {}", e));
                Ok(true)
            }
            Msg::ReassignGidNumbers => {
                let vars = reassign_gid_numbers::Variables {};
                self.common.call_graphql::<ReassignGidNumbers, _>(
                    ctx,
                    vars,
                    Msg::ReassignResponse,
                    "Failed to reassign gidNumbers",
                );
                Ok(false)
            }
            Msg::ReassignResponse(Ok(data)) => {
                let resp = data.reassign_gid_numbers;
                ctx.props().on_status_update.emit(if resp.success {
                    "✅ All group gidNumbers reassigned successfully".to_string()
                } else {
                    format!("❌ {}", resp.message)
                });
                Ok(true)
            }
            Msg::ReassignResponse(Err(e)) => {
                ctx.props().on_status_update.emit(format!("❌ Failed to reassign gidNumbers: {}", e));
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for PosixOptions {
    type Message = Msg;
    type Properties = PosixOptionsProps;

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Msg::LoadConfig);
        Self {
            common: CommonComponentParts::<Self>::create(),
            auto_gid_enabled: true,
            gid_start: "3001".to_string(),
            config_changed: false,
            loading: true,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.handle_msg(ctx, msg).unwrap_or(false)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

        let on_auto_gid = link.callback(|e: Event| {
            let checked = e.target().unwrap()
                .dyn_into::<web_sys::HtmlInputElement>().unwrap()
                .checked();
            Msg::UpdateAutoGid(checked)
        });

        let on_gid_start = link.callback(|e: InputEvent| {
            Msg::UpdateGidStart(
                e.target().unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>().unwrap()
                    .value()
            )
        });

        let on_save = link.callback(|_| Msg::SaveConfig);
        let on_reassign = link.callback(|_| Msg::ReassignGidNumbers);

        let reassign_disabled = !self.config_changed || self.loading;

        html! {
            <div class="row">
                <div class="col-12">
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5>{ "POSIX Attributes (gidNumber for groups)" }</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-8">
                                    <div class="form-check mb-3">
                                        <input type="checkbox" class="form-check-input" checked={self.auto_gid_enabled} onchange={on_auto_gid} disabled={self.loading} />
                                        <label class="form-check-label">{ "Automatically assign gidNumber to new groups" }</label>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">{ "Starting gidNumber" }</label>
                                        <input type="number" class="form-control" value={self.gid_start.clone()} oninput={on_gid_start} min="1000" disabled={self.loading} />
                                        <small class="text-muted">{ "Default: 3001. Numbers below this are reserved for system use." }</small>
                                    </div>
                                </div>

                                <div class="col-md-4 d-flex align-items-end">
                                    <button onclick={on_save} class="btn btn-success w-100 mb-3" disabled={self.loading || !self.config_changed}>
                                        { "Save POSIX Config" }
                                    </button>
                                </div>
                            </div>

                            <div class="mt-4 border-top pt-3">
                                <button onclick={on_reassign} class="btn btn-warning w-100" disabled={reassign_disabled}>
                                    { "Reassign existing group gidNumbers" }
                                </button>
                                <small class="text-danger d-block mt-1">
                                    { "Only enabled after config change. Will rewrite gidNumber on EVERY group." }
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}
