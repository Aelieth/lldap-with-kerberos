use crate::{
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use yew::prelude::*;
use yew::events::InputEvent;
use wasm_bindgen::JsCast;
use graphql_client::GraphQLQuery;
use anyhow::Result;
use super::posix_options::PosixOptions;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "../schema.graphql", query_path = "src/queries/export_keytab.graphql", response_derives = "Debug")]
pub struct ExportKeytabForKeycloak;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "../schema.graphql", query_path = "src/queries/keycloak_suggested_config.graphql", response_derives = "Debug")]
pub struct KeycloakSuggestedConfig;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "../schema.graphql", query_path = "src/queries/keycloak_config.graphql", response_derives = "Debug")]
pub struct KeycloakConfig;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "../schema.graphql", query_path = "src/queries/test_keycloak_connection.graphql", response_derives = "Debug")]
pub struct TestKeycloakConnection;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "../schema.graphql", query_path = "src/queries/save_keycloak_config.graphql", response_derives = "Debug")]
pub struct SaveKeycloakConfig;

#[derive(GraphQLQuery)]
#[graphql(schema_path = "../schema.graphql", query_path = "src/queries/push_realm_to_keycloak.graphql", response_derives = "Debug")]
pub struct PushRealmToKeycloak;

pub struct Federation {
    common: CommonComponentParts<Self>,
    keycloak_url: String,
    realm: String,
    admin_username: String,
    admin_password: String,
    suggested_url: String,
    suggested_realm: String,
    suggested_admin_username: String,
    connection_status: String,
    loaded_from_toml: bool,
    connection_tested_successfully: bool,

    new_realm_name: String,
    lldap_url: String,
    sync_username: String,
    sync_password: String,
    enable_hsts: bool,
    enable_brute_force: bool,
}

pub enum Msg {
    LoadConfigs,
    TestConnection,
    SaveSettings,
    UpdateKeycloakUrl(String),
    UpdateRealm(String),
    UpdateAdminUsername(String),
    UpdateAdminPassword(String),
    UpdateNewRealmName(String),
    UpdateLldapUrl(String),
    UpdateSyncUsername(String),
    UpdateSyncPassword(String),
    ToggleHsts,
    ToggleBruteForce,
    PosixStatus(String),
    ExportKeytab,
    PushRealmToKeycloak,
    ConfigResponse(Result<keycloak_config::ResponseData>),
    SuggestedResponse(Result<keycloak_suggested_config::ResponseData>),
    TestResponse(Result<test_keycloak_connection::ResponseData>),
    SaveResponse(Result<save_keycloak_config::ResponseData>),
    ExportResponse(Result<export_keytab_for_keycloak::ResponseData>),
    PushResponse(Result<push_realm_to_keycloak::ResponseData>),
}

impl CommonComponent<Federation> for Federation {
    fn handle_msg(&mut self, ctx: &Context<Self>, msg: <Self as Component>::Message) -> anyhow::Result<bool> {
        match msg {
            Msg::LoadConfigs => {
                let vars = keycloak_config::Variables {};
                self.common.call_graphql::<KeycloakConfig, _>(ctx, vars, Msg::ConfigResponse, "Failed to load saved config");
                let vars2 = keycloak_suggested_config::Variables {};
                self.common.call_graphql::<KeycloakSuggestedConfig, _>(ctx, vars2, Msg::SuggestedResponse, "Failed to load suggested config");
                self.connection_status = "Loading...".to_string();
                Ok(true)
            }
            Msg::TestConnection => {
                let variables = test_keycloak_connection::Variables {
                    input: test_keycloak_connection::TestKeycloakConnectionInput {
                        url: self.keycloak_url.clone(),
                        realm: self.realm.clone(),
                        adminUser: self.admin_username.clone(),
                        adminPass: self.admin_password.clone(),
                    },
                };
                self.common.call_graphql::<TestKeycloakConnection, _>(ctx, variables, Msg::TestResponse, "Error testing connection");
                self.connection_status = "Testing...".to_string();
                Ok(true)
            }
            Msg::SaveSettings => {
                let variables = save_keycloak_config::Variables {
                    input: save_keycloak_config::SaveKeycloakConfigInput {
                        url: self.keycloak_url.clone(),
                        realm: self.realm.clone(),
                        adminUser: self.admin_username.clone(),
                    },
                };
                self.common.call_graphql::<SaveKeycloakConfig, _>(ctx, variables, Msg::SaveResponse, "Error saving config");
                self.connection_status = "Saving...".to_string();
                Ok(true)
            }
            Msg::UpdateKeycloakUrl(s) => { self.keycloak_url = s; self.loaded_from_toml = true; Ok(true) }
            Msg::UpdateRealm(s) => { self.realm = s; self.loaded_from_toml = true; Ok(true) }
            Msg::UpdateAdminUsername(s) => { self.admin_username = s; self.loaded_from_toml = true; Ok(true) }
            Msg::UpdateAdminPassword(s) => { self.admin_password = s; Ok(true) }
            Msg::UpdateNewRealmName(s) => { self.new_realm_name = s; Ok(true) }
            Msg::UpdateLldapUrl(s) => { self.lldap_url = s; Ok(true) }
            Msg::UpdateSyncUsername(s) => { self.sync_username = s; Ok(true) }
            Msg::UpdateSyncPassword(s) => { self.sync_password = s; Ok(true) }
            Msg::ToggleHsts => { self.enable_hsts = !self.enable_hsts; Ok(true) }
            Msg::ToggleBruteForce => { self.enable_brute_force = !self.enable_brute_force; Ok(true) }
            Msg::PosixStatus(s) => {
                self.connection_status = s;
                Ok(true)
            }
            Msg::ExportKeytab => {
                let variables = export_keytab_for_keycloak::Variables { hostname: "keycloak".to_string() };
                self.common.call_graphql::<ExportKeytabForKeycloak, _>(ctx, variables, Msg::ExportResponse, "Error exporting keytab");
                self.connection_status = "Exporting keytab...".to_string();
                Ok(true)
            }
            Msg::PushRealmToKeycloak => {
                let variables = push_realm_to_keycloak::Variables {
                    url: self.keycloak_url.clone(),
                    realm: self.new_realm_name.clone(),
                    admin_user: self.admin_username.clone(),
                    admin_pass: self.admin_password.clone(),
                    lldap_url: self.lldap_url.clone(),
                    sync_username: self.sync_username.clone(),
                    sync_password: self.sync_password.clone(),
                };
                self.common.call_graphql::<PushRealmToKeycloak, _>(ctx, variables, Msg::PushResponse, "Error pushing realm");
                self.connection_status = "Pushing realm to Keycloak...".to_string();
                Ok(true)
            }
            Msg::ConfigResponse(Ok(data)) => {
                let cfg = data.keycloak_config;
                if !self.loaded_from_toml {
                    self.keycloak_url = cfg.url;
                    self.realm = cfg.realm;
                    self.admin_username = cfg.admin_user;
                    self.loaded_from_toml = true;
                }
                Ok(true)
            }
            Msg::SuggestedResponse(Ok(data)) => {
                let s = data.keycloak_suggested_config;
                self.suggested_url = s.url;
                self.suggested_realm = s.realm.clone();
                self.suggested_admin_username = s.admin_username;
                if self.new_realm_name.is_empty() { self.new_realm_name = s.realm.clone(); }
                if self.lldap_url.is_empty() { self.lldap_url = "ldap://lldap:3890".to_string(); }
                if self.sync_username.is_empty() { self.sync_username = "keycloak".to_string(); }
                Ok(true)
            }
            Msg::TestResponse(Ok(data)) => {
                self.connection_status = data.test_keycloak_connection.message.clone();
                self.connection_tested_successfully = data.test_keycloak_connection.ok;
                Ok(true)
            }
            Msg::SaveResponse(Ok(data)) => { self.connection_status = data.save_keycloak_config.message; Ok(true) }
            Msg::TestResponse(Err(e)) | Msg::SaveResponse(Err(e)) | Msg::SuggestedResponse(Err(e)) | Msg::ConfigResponse(Err(e)) => {
                self.connection_status = format!("❌ {}", e);
                Ok(true)
            }
            Msg::PushResponse(Ok(data)) => { self.connection_status = data.push_realm_to_keycloak.message; Ok(true) }
            Msg::PushResponse(Err(e)) => { self.connection_status = format!("❌ {}", e); Ok(true) }
            Msg::ExportResponse(Ok(data)) => {
                let resp = data.export_keytab_for_keycloak;
                self.connection_status = if resp.ok { format!("✅ Keytab saved to {}", resp.path) } else { format!("❌ {}", resp.error_msg) };
                Ok(true)
            }
            Msg::ExportResponse(Err(e)) => { self.connection_status = format!("❌ {}", e); Ok(true) }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> { &mut self.common }
}

impl Component for Federation {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Msg::LoadConfigs);
        Federation {
            common: CommonComponentParts::<Self>::create(),
            keycloak_url: "".to_string(),
            realm: "".to_string(),
            admin_username: "admin".to_string(),
            admin_password: "".to_string(),
            suggested_url: "".to_string(),
            suggested_realm: "".to_string(),
            suggested_admin_username: "".to_string(),
            connection_status: "Loading...".to_string(),
            loaded_from_toml: false,
            connection_tested_successfully: false,

            new_realm_name: "".to_string(),
            lldap_url: "ldap://lldap:3890".to_string(),
            sync_username: "keycloak".to_string(),
            sync_password: "".to_string(),
            enable_hsts: false,
            enable_brute_force: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.handle_msg(ctx, msg).unwrap_or(false)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let on_test = ctx.link().callback(|_| Msg::TestConnection);
        let on_save = ctx.link().callback(|_| Msg::SaveSettings);
        let on_export = ctx.link().callback(|_| Msg::ExportKeytab);
        let on_push = ctx.link().callback(|_| Msg::PushRealmToKeycloak);

        let on_keycloak_url = ctx.link().callback(|e: InputEvent| Msg::UpdateKeycloakUrl(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_realm = ctx.link().callback(|e: InputEvent| Msg::UpdateRealm(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_admin_username = ctx.link().callback(|e: InputEvent| Msg::UpdateAdminUsername(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_admin_password = ctx.link().callback(|e: InputEvent| Msg::UpdateAdminPassword(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));

        let on_new_realm_name = ctx.link().callback(|e: InputEvent| Msg::UpdateNewRealmName(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_lldap_url = ctx.link().callback(|e: InputEvent| Msg::UpdateLldapUrl(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_sync_username = ctx.link().callback(|e: InputEvent| Msg::UpdateSyncUsername(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_sync_password = ctx.link().callback(|e: InputEvent| Msg::UpdateSyncPassword(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));

        let on_hsts = ctx.link().callback(|_| Msg::ToggleHsts);
        let on_brute = ctx.link().callback(|_| Msg::ToggleBruteForce);

        let push_enabled = self.connection_tested_successfully && !self.sync_password.is_empty();

        // NEW: PosixOptions status callback
        let on_posix_status = ctx.link().callback(Msg::PosixStatus);

        html! {
            <div class="container">
                <div class="row">
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h2>{ "Federation - Keycloak + POSIX Settings" }</h2>
                        </div>
                        <div class="alert alert-info">{ &self.connection_status }</div>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-header"><h5>{ "Keycloak Connection Settings" }</h5></div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <label class="form-label">{ "Keycloak URL" }</label>
                                    <input type="url" class="form-control" value={self.keycloak_url.clone()} oninput={on_keycloak_url} />
                                    <small class="text-muted">{ format!("Suggested: {}:8080", self.suggested_url) }</small>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">{ "Realm" }</label>
                                    <input type="text" class="form-control" value={self.realm.clone()} oninput={on_realm} />
                                    <small class="text-muted">{ format!("Suggested: {}", self.suggested_realm) }</small>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">{ "Admin Username" }</label>
                                    <input type="text" class="form-control" value={self.admin_username.clone()} oninput={on_admin_username} />
                                    <small class="text-muted">{ format!("Suggested: {}", self.suggested_admin_username) }</small>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">{ "Admin Password" }</label>
                                    <input type="password" class="form-control" value={self.admin_password.clone()} oninput={on_admin_password} placeholder="LLDAP_KEYCLOAK_ADMIN_PASS" />
                                </div>
                            </div>
                            <div class="card-footer text-end">
                                <button onclick={on_test} class="btn btn-primary me-2">{ "Test Settings" }</button>
                                <button onclick={&on_save} class="btn btn-success">{ "Save Changes" }</button>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-header"><h5>{ "New Realm Settings" }</h5></div>
                            <div class="card-body">
                                <div class={if self.connection_tested_successfully { "" } else { "opacity-50 pe-none" }}>
                                    <div class="mb-3">
                                        <label class="form-label">{ "Realm Name" }</label>
                                        <input type="text" class="form-control" value={self.new_realm_name.clone()} oninput={on_new_realm_name} />
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">{ "LLDAP URL" }</label>
                                        <input type="text" class="form-control" value={self.lldap_url.clone()} oninput={on_lldap_url} />
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">{ "Sync Username" }</label>
                                        <input type="text" class="form-control" value={self.sync_username.clone()} oninput={on_sync_username} />
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">{ "Sync Password" } <span class="text-danger">{ "*" }</span></label>
                                        <input type="password" class="form-control" value={self.sync_password.clone()} oninput={on_sync_password} placeholder="REQUIRED - used for bind DN" />
                                    </div>
                                    <div class="form-check mb-2">
                                        <input type="checkbox" class="form-check-input" checked={self.enable_hsts} onchange={on_hsts} />
                                        <label class="form-check-label">{ "Enable HSTS" }</label>
                                    </div>
                                    <div class="form-check mb-3">
                                        <input type="checkbox" class="form-check-input" checked={self.enable_brute_force} onchange={on_brute} />
                                        <label class="form-check-label">{ "Enable Brute Force Protection" }</label>
                                    </div>
                                </div>
                            </div>
                            <div class="card-footer text-end">
                                <button onclick={on_export} class="btn btn-primary me-2">{ "Export keytab" }</button>
                                <button onclick={on_push} class={if push_enabled { "btn btn-danger flex-fill" } else { "btn btn-secondary flex-fill disabled" }} disabled={!push_enabled}>
                                    { "Push To Keycloak" }
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                // POSIX modular component
                <PosixOptions on_status_update={on_posix_status} />
            </div>
        }
    }
}
