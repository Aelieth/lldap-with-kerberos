use crate::{
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use yew::prelude::*;
use yew::events::InputEvent;
use web_sys::window;
use wasm_bindgen::JsCast;
use serde_json::json;
use graphql_client::GraphQLQuery;
use anyhow::Result;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "src/queries/export_keytab.graphql",
    response_derives = "Debug"
)]
pub struct ExportKeytabForKeycloak;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "src/queries/keycloak_suggested_config.graphql",
    response_derives = "Debug"
)]
pub struct KeycloakSuggestedConfig;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "src/queries/keycloak_config.graphql",
    response_derives = "Debug"
)]
pub struct KeycloakConfig;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "src/queries/test_keycloak_connection.graphql",
    response_derives = "Debug"
)]
pub struct TestKeycloakConnection;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "src/queries/save_keycloak_config.graphql",
    response_derives = "Debug"
)]
pub struct SaveKeycloakConfig;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "src/queries/push_realm_to_keycloak.graphql",
    response_derives = "Debug"
)]
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
    use_ldaps: bool,
    enable_hsts: bool,
    enable_brute_force: bool,
    ticket_lifetime: String,
    renew_lifetime: String,
    forwardable: bool,
    rdns: bool,
    new_realm_mode: bool,
    new_realm_name: String,
    sync_username: String,
    sync_password: String,
    connection_tested_successfully: bool,
}

pub enum Msg {
    LoadConfigs,
    TestConnection,
    SaveSettings,
    UpdateUrl(String),
    UpdateRealm(String),
    UpdateUsername(String),
    UpdatePassword(String),
    ToggleLdaps,
    ToggleHsts,
    ToggleBruteForce,
    UpdateTicketLifetime(String),
    UpdateRenewLifetime(String),
    ToggleForwardable,
    ToggleRdns,
    ToggleNewRealm,
    UpdateNewRealmName(String),
    UpdateSyncUsername(String),
    UpdateSyncPassword(String),
    GenerateRealmJson,
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
            Msg::UpdateUrl(s) => { self.keycloak_url = s; self.loaded_from_toml = true; Ok(true) }
            Msg::UpdateRealm(s) => { self.realm = s; self.loaded_from_toml = true; Ok(true) }
            Msg::UpdateUsername(s) => { self.admin_username = s; self.loaded_from_toml = true; Ok(true) }
            Msg::UpdatePassword(s) => { self.admin_password = s; Ok(true) }
            Msg::ToggleLdaps => { self.use_ldaps = !self.use_ldaps; Ok(true) }
            Msg::ToggleHsts => { self.enable_hsts = !self.enable_hsts; Ok(true) }
            Msg::ToggleBruteForce => { self.enable_brute_force = !self.enable_brute_force; Ok(true) }
            Msg::UpdateTicketLifetime(s) => { self.ticket_lifetime = s; Ok(true) }
            Msg::UpdateRenewLifetime(s) => { self.renew_lifetime = s; Ok(true) }
            Msg::ToggleForwardable => { self.forwardable = !self.forwardable; Ok(true) }
            Msg::ToggleRdns => { self.rdns = !self.rdns; Ok(true) }
            Msg::ToggleNewRealm => {
                self.new_realm_mode = !self.new_realm_mode;
                if self.new_realm_mode && self.new_realm_name.trim().is_empty() {
                    self.new_realm_name = if self.realm.trim().is_empty() {
                        self.suggested_realm.clone()
                    } else {
                        self.realm.clone()
                    };
                }
                Ok(true)
            }
            Msg::UpdateNewRealmName(s) => { self.new_realm_name = s; Ok(true) }
            Msg::UpdateSyncUsername(s) => { self.sync_username = s; Ok(true) }
            Msg::UpdateSyncPassword(s) => { self.sync_password = s; Ok(true) }
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
                self.suggested_realm = s.realm;
                self.suggested_admin_username = s.admin_username;
                Ok(true)
            }
            Msg::TestResponse(Ok(data)) => {
                self.connection_status = data.test_keycloak_connection.message;
                self.connection_tested_successfully = true;
                Ok(true)
            }
            Msg::SaveResponse(Ok(data)) => { self.connection_status = data.save_keycloak_config.message; Ok(true) }
            Msg::TestResponse(Err(e)) | Msg::SaveResponse(Err(e)) | Msg::SuggestedResponse(Err(e)) | Msg::ConfigResponse(Err(e)) => {
                self.connection_status = format!("❌ {}", e);
                Ok(true)
            }
            Msg::GenerateRealmJson => {
                let realm_lower = if self.new_realm_mode && !self.new_realm_name.trim().is_empty() {
                    self.new_realm_name.to_lowercase()
                } else if self.realm.trim().is_empty() {
                    self.suggested_realm.clone()
                } else {
                    self.realm.to_lowercase()
                };
                let realm_upper = realm_lower.to_uppercase();
                let base_dn = format!("dc={}", realm_lower.replace('.', ",dc="));
                let connection_url = if self.use_ldaps { "ldaps://lldap:636".to_string() } else { "ldap://lldap:389".to_string() };
                let ssl_required = if self.use_ldaps { "external" } else { "none" };
                let (bind_dn, bind_cred) = if self.new_realm_mode && !self.sync_username.trim().is_empty() {
                    let dn = format!("uid={},ou=people,{}", self.sync_username, base_dn);
                    let cred = if !self.sync_password.trim().is_empty() {
                        self.sync_password.clone()
                    } else {
                        "<ENTER YOUR KEYCLOAK BIND PASSWORD HERE AFTER IMPORT>".to_string()
                    };
                    (dn, cred)
                } else {
                    (format!("uid=keycloak,ou=people,{}", base_dn), "<ENTER YOUR KEYCLOAK BIND PASSWORD HERE AFTER IMPORT>".to_string())
                };
                let realm_json = json!({
                    "realm": realm_lower,
                    "enabled": true,
                    "sslRequired": ssl_required,
                    "registrationAllowed": false,
                    "resetPasswordAllowed": false,
                    "rememberMe": true,
                    "editUsernameAllowed": false,
                    "verifyEmail": false,
                    "loginWithEmailAllowed": false,
                    "duplicateEmailsAllowed": false,
                    "registrationEmailAsUsername": false,
                    "ssoSessionMaxLifespan": 43200,
                    "accessTokenLifespan": 900,
                    "clients": [{
                        "clientId": "lldap-web",
                        "name": "LLDAP Web Apps",
                        "enabled": true,
                        "protocol": "openid-connect",
                        "publicClient": true,
                        "standardFlowEnabled": true,
                        "implicitFlowEnabled": true,
                        "directAccessGrantsEnabled": true,
                        "redirectUris": ["*"],
                        "webOrigins": ["+"]
                    }],
                    "components": {
                        "org.keycloak.storage.UserStorageProvider": [{
                            "name": "lldap-with-kerberos",
                            "providerId": "ldap",
                            "providerType": "org.keycloak.storage.UserStorageProvider",
                            "config": {
                                "vendor": ["other"],
                                "connectionUrl": [connection_url],
                                "bindDn": [bind_dn],
                                "bindCredential": [bind_cred],
                                "usersDn": [format!("ou=people,{}", base_dn)],
                                "groupsDn": [format!("ou=groups,{}", base_dn)],
                                "userObjectClasses": ["inetOrgPerson", "organizationalPerson"],
                                "rdnLDAPAttribute": ["uid"],
                                "uuidLDAPAttribute": ["entryUUID"],
                                "usernameLDAPAttribute": ["uid"],
                                "searchScope": ["subtree"],
                                "validatePasswordPolicy": ["false"],
                                "trustEmail": ["true"],
                                "syncRegistrations": ["true"],
                                "editMode": ["READ_ONLY"],
                                "importEnabled": ["true"],
                                "pagination": ["true"],
                                "allowKerberosAuthentication": ["true"],
                                "kerberosRealm": [realm_upper],
                                "serverPrincipal": [format!("HTTP/keycloak.{}@{}", base_dn.replace("dc=", "").replace(',', "."), realm_upper)],
                                "keyTab": ["/keytabs/keycloak-http.keytab"],
                                "krbPrincipalAttribute": ["krbPrincipalName"],
                                "useKerberosForPasswordAuthentication": ["false"],
                                "useTruststoreSpi": ["always"],
                                "connectionPooling": ["true"],
                                "cachePolicy": ["DEFAULT"],
                                "usePasswordModifyExtendedOp": ["false"],
                                "connectionTrace": ["false"]
                            }
                        }]
                    },
                    "browserSecurityHeaders": {
                        "strictTransportSecurity": if self.enable_hsts { "max-age=31536000; includeSubDomains" } else { "" },
                        "xFrameOptions": "SAMEORIGIN",
                        "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
                        "contentSecurityPolicyReportOnly": "",
                        "xContentTypeOptions": "nosniff",
                        "xRobotsTag": "none",
                        "referrerPolicy": "no-referrer"
                    },
                    "bruteForceProtected": self.enable_brute_force,
                    "_comment": "Generated by LLDAP+Kerberos Federation page"
                });
                let json_str = serde_json::to_string_pretty(&realm_json).unwrap();
                let data_url = format!("data:application/json;charset=utf-8,{}", json_str);
                if let Some(window) = window() {
                    let document = window.document().unwrap();
                    let a = document.create_element("a").unwrap();
                    let a: web_sys::HtmlElement = a.dyn_into().unwrap();
                    a.set_attribute("href", &data_url).unwrap();
                    a.set_attribute("download", &format!("{}-realm.json", realm_lower)).unwrap();
                    a.click();
                }
                self.connection_status = format!("✅ Downloaded {}-realm.json", realm_lower);
                Ok(true)
            }
            Msg::ExportKeytab => {
                let variables = export_keytab_for_keycloak::Variables { hostname: "keycloak".to_string() };
                self.common.call_graphql::<ExportKeytabForKeycloak, _>(ctx, variables, Msg::ExportResponse, "Error exporting keytab");
                self.connection_status = "Exporting keytab...".to_string();
                Ok(true)
            }
            Msg::PushRealmToKeycloak => {
                let realm_lower = if self.new_realm_mode && !self.new_realm_name.trim().is_empty() {
                    self.new_realm_name.to_lowercase()
                } else if self.realm.trim().is_empty() {
                    self.suggested_realm.clone()
                } else {
                    self.realm.to_lowercase()
                };
                let realm_upper = realm_lower.to_uppercase();
                let base_dn = format!("dc={}", realm_lower.replace('.', ",dc="));
                let connection_url = if self.use_ldaps { "ldaps://lldap:636".to_string() } else { "ldap://lldap:389".to_string() };
                let ssl_required = if self.use_ldaps { "external" } else { "none" };
                let (bind_dn, bind_cred) = if self.new_realm_mode && !self.sync_username.trim().is_empty() {
                    let dn = format!("uid={},ou=people,{}", self.sync_username, base_dn);
                    let cred = if !self.sync_password.trim().is_empty() {
                        self.sync_password.clone()
                    } else {
                        "<ENTER YOUR KEYCLOAK BIND PASSWORD HERE AFTER IMPORT>".to_string()
                    };
                    (dn, cred)
                } else {
                    (format!("uid=keycloak,ou=people,{}", base_dn), "<ENTER YOUR KEYCLOAK BIND PASSWORD HERE AFTER IMPORT>".to_string())
                };
                let realm_json = json!({
                    "realm": realm_lower,
                    "enabled": true,
                    "sslRequired": ssl_required,
                    "registrationAllowed": false,
                    "resetPasswordAllowed": false,
                    "rememberMe": true,
                    "editUsernameAllowed": false,
                    "verifyEmail": false,
                    "loginWithEmailAllowed": false,
                    "duplicateEmailsAllowed": false,
                    "registrationEmailAsUsername": false,
                    "ssoSessionMaxLifespan": 43200,
                    "accessTokenLifespan": 900,
                    "clients": [{
                        "clientId": "lldap-web",
                        "name": "LLDAP Web Apps",
                        "enabled": true,
                        "protocol": "openid-connect",
                        "publicClient": true,
                        "standardFlowEnabled": true,
                        "implicitFlowEnabled": true,
                        "directAccessGrantsEnabled": true,
                        "redirectUris": ["*"],
                        "webOrigins": ["+"]
                    }],
                    "components": {
                        "org.keycloak.storage.UserStorageProvider": [{
                            "name": "lldap-with-kerberos",
                            "providerId": "ldap",
                            "providerType": "org.keycloak.storage.UserStorageProvider",
                            "config": {
                                "vendor": ["other"],
                                "connectionUrl": [connection_url],
                                "bindDn": [bind_dn],
                                "bindCredential": [bind_cred],
                                "usersDn": [format!("ou=people,{}", base_dn)],
                                       "groupsDn": [format!("ou=groups,{}", base_dn)],
                                       "userObjectClasses": ["inetOrgPerson", "organizationalPerson"],
                                       "rdnLDAPAttribute": ["uid"],
                                       "uuidLDAPAttribute": ["entryUUID"],
                                       "usernameLDAPAttribute": ["uid"],
                                       "searchScope": ["subtree"],
                                       "validatePasswordPolicy": ["false"],
                                       "trustEmail": ["true"],
                                       "syncRegistrations": ["true"],
                                       "editMode": ["READ_ONLY"],
                                       "importEnabled": ["true"],
                                       "pagination": ["true"],
                                       "allowKerberosAuthentication": ["true"],
                                       "kerberosRealm": [realm_upper],
                                       "serverPrincipal": [format!("HTTP/keycloak.{}@{}", base_dn.replace("dc=", "").replace(',', "."), realm_upper)],
                                       "keyTab": ["/keytabs/keycloak-http.keytab"],
                                       "krbPrincipalAttribute": ["krbPrincipalName"],
                                       "useKerberosForPasswordAuthentication": ["false"],
                                       "useTruststoreSpi": ["always"],
                                       "connectionPooling": ["true"],
                                       "cachePolicy": ["DEFAULT"],
                                       "usePasswordModifyExtendedOp": ["false"],
                                       "connectionTrace": ["false"]
                            }
                        }]
                    },
                    "browserSecurityHeaders": {
                        "strictTransportSecurity": if self.enable_hsts { "max-age=31536000; includeSubDomains" } else { "" },
                        "xFrameOptions": "SAMEORIGIN",
                        "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
                        "contentSecurityPolicyReportOnly": "",
                        "xContentTypeOptions": "nosniff",
                        "xRobotsTag": "none",
                        "referrerPolicy": "no-referrer"
                    },
                    "bruteForceProtected": self.enable_brute_force,
                    "_comment": "Generated by LLDAP+Kerberos Federation page"
                });
                let json_str = serde_json::to_string_pretty(&realm_json).unwrap();
                let variables = push_realm_to_keycloak::Variables {
                    url: self.keycloak_url.clone(),
                    realm: realm_lower.clone(),
                    admin_user: self.admin_username.clone(),
                    admin_pass: self.admin_password.clone(),   // ← now uses the real Admin Password from Connection Options
                    json: json_str,
                };
                self.common.call_graphql::<PushRealmToKeycloak, _>(
                    ctx,
                    variables,
                    Msg::PushResponse,
                    "Error pushing realm",
                );
                self.connection_status = "Pushing realm to Keycloak...".to_string();
                Ok(true)
            }
            Msg::PushResponse(Ok(data)) => {
                self.connection_status = data.push_realm_to_keycloak.message;
                Ok(true)
            }
            Msg::PushResponse(Err(e)) => {
                self.connection_status = format!("❌ {}", e);
                Ok(true)
            }
            Msg::ExportResponse(Ok(data)) => {
                let resp = data.export_keytab_for_keycloak;
                self.connection_status = if resp.ok { format!("✅ Keytab saved to {}", resp.path) } else { format!("❌ {}", resp.error_msg) };
                Ok(true)
            }
            Msg::ExportResponse(Err(e)) => {
                self.connection_status = format!("❌ {}", e);
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
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
            use_ldaps: false,
            enable_hsts: false,
            enable_brute_force: false,
            ticket_lifetime: "24h".to_string(),
            renew_lifetime: "7d".to_string(),
            forwardable: true,
            rdns: false,
            new_realm_mode: false,
            new_realm_name: "".to_string(),
            sync_username: "keycloak".to_string(),
            sync_password: "".to_string(),
            connection_tested_successfully: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.handle_msg(ctx, msg).unwrap_or(false)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let on_test = ctx.link().callback(|_| Msg::TestConnection);
        let on_save = ctx.link().callback(|_| Msg::SaveSettings);
        let on_generate = ctx.link().callback(|_| Msg::GenerateRealmJson);
        let on_export = ctx.link().callback(|_| Msg::ExportKeytab);
        let on_api_push = ctx.link().callback(|_| Msg::PushRealmToKeycloak);

        let on_url = ctx.link().callback(|e: InputEvent| Msg::UpdateUrl(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_realm = ctx.link().callback(|e: InputEvent| Msg::UpdateRealm(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_username = ctx.link().callback(|e: InputEvent| Msg::UpdateUsername(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_password = ctx.link().callback(|e: InputEvent| Msg::UpdatePassword(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));

        let on_ldaps = ctx.link().callback(|_| Msg::ToggleLdaps);
        let on_hsts = ctx.link().callback(|_| Msg::ToggleHsts);
        let on_brute = ctx.link().callback(|_| Msg::ToggleBruteForce);

        let on_ticket = ctx.link().callback(|e: InputEvent| Msg::UpdateTicketLifetime(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_renew = ctx.link().callback(|e: InputEvent| Msg::UpdateRenewLifetime(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_forwardable = ctx.link().callback(|_| Msg::ToggleForwardable);
        let on_rdns = ctx.link().callback(|_| Msg::ToggleRdns);

        let on_new_realm = ctx.link().callback(|_| Msg::ToggleNewRealm);
        let on_new_realm_name = ctx.link().callback(|e: InputEvent| Msg::UpdateNewRealmName(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_sync_user = ctx.link().callback(|e: InputEvent| Msg::UpdateSyncUsername(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_sync_pass = ctx.link().callback(|e: InputEvent| Msg::UpdateSyncPassword(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));

        html! {
            <div class="container">
                <div class="row">
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h2>{ "Federation - Keycloak + Kerberos Settings" }</h2>
                        </div>
                        <div class="alert alert-info">{ &self.connection_status }</div>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-header"><h5>{ "Connection Options" }</h5></div>
                            <div class="card-body">
                                <div class="mb-3 row">
                                    <label class="col-sm-4 col-form-label">{ "Keycloak URL" }</label>
                                    <div class="col-sm-8">
                                        <input type="url" class="form-control" value={self.keycloak_url.clone()} oninput={on_url} />
                                        <small class="text-muted">{ format!("Suggested: {}:8080", self.suggested_url) }</small>
                                    </div>
                                </div>
                                <div class="mb-3 row">
                                    <label class="col-sm-4 col-form-label">{ "Realm" }</label>
                                    <div class="col-sm-8">
                                        <input type="text" class="form-control" value={self.realm.clone()} oninput={on_realm} />
                                        <small class="text-muted">{ format!("Suggested: {}", self.suggested_realm) }</small>
                                    </div>
                                </div>
                                <div class="mb-3 row">
                                    <label class="col-sm-4 col-form-label">{ "Admin Username" }</label>
                                    <div class="col-sm-8">
                                        <input type="text" class="form-control" value={self.admin_username.clone()} oninput={on_username} />
                                        <small class="text-muted">{ format!("Suggested: {}", self.suggested_admin_username) }</small>
                                    </div>
                                </div>
                                <div class="mb-3 row">
                                    <label class="col-sm-4 col-form-label">{ "Admin Password" }</label>
                                    <div class="col-sm-8">
                                        <input type="password" class="form-control" value={self.admin_password.clone()} oninput={on_password} placeholder="LLDAP_KEYCLOAK_ADMIN_PASS" />
                                    </div>
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
                            <div class="card-header"><h5>{ "Keycloak Realm Settings" }</h5></div>
                            <div class="card-body">
                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" checked={self.use_ldaps} onchange={on_ldaps} />
                                    <label class="form-check-label">{ "Use LDAPS (port 636)" }</label>
                                </div>
                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" checked={self.enable_hsts} onchange={on_hsts} />
                                    <label class="form-check-label">{ "Enable HSTS" }</label>
                                </div>
                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" checked={self.enable_brute_force} onchange={on_brute} />
                                    <label class="form-check-label">{ "Enable Brute Force Protection" }</label>
                                </div>

                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" checked={self.new_realm_mode} onchange={on_new_realm} />
                                    <label class="form-check-label">{ "New Realm (one-time setup)" }</label>
                                </div>

                                { if self.new_realm_mode {
                                    html! {
                                        <div class="mt-3 border p-3 bg-light rounded">
                                            <div class="mb-3 row">
                                                <label class="col-sm-4 col-form-label">{ "Realm name" }</label>
                                                <div class="col-sm-8">
                                                    <input type="text" class="form-control" value={self.new_realm_name.clone()} oninput={on_new_realm_name} />
                                                    <small class="text-muted">{ format!("Suggested: {}", self.suggested_realm) }</small>
                                                </div>
                                            </div>
                                            <div class="mb-3 row">
                                                <label class="col-sm-4 col-form-label">{ "Sync username" }</label>
                                                <div class="col-sm-8">
                                                    <input type="text" class="form-control" value={self.sync_username.clone()} oninput={on_sync_user} placeholder="keycloak" />
                                                </div>
                                            </div>
                                            <div class="mb-3 row">
                                                <label class="col-sm-4 col-form-label">{ "Sync password" }</label>
                                                <div class="col-sm-8">
                                                    <input type="password" class="form-control" value={self.sync_password.clone()} oninput={on_sync_pass} placeholder="one-time bind password" />
                                                </div>
                                            </div>
                                        </div>
                                    }
                                } else { html! {} }}
                            </div>

                            <div class="card-footer d-flex gap-2">
                                <button onclick={on_export} class="btn btn-success flex-fill">{ "Export keytab" }</button>
                                <button onclick={on_generate} class="btn btn-success flex-fill">{ "Generate & Download realm.json" }</button>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row">
                    <div class="col-12">
                        <div class="card mb-4">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">{ "Keycloak API Realm Push" }</h5>
                                <button
                                    onclick={on_api_push}
                                    class={if self.connection_tested_successfully && self.new_realm_mode { "btn btn-danger" } else { "btn btn-secondary disabled" }}
                                    disabled={!(self.connection_tested_successfully && self.new_realm_mode)}
                                >
                                    { "Push Realm Now" }
                                </button>
                            </div>
                            <div class="card-body">
                                { if !(self.connection_tested_successfully && self.new_realm_mode) {
                                    html! {
                                        <div class="alert alert-secondary">
                                            {"Test and Save your Keycloak Connection Options, then check \"New Realm\" to enable the API Push button."}
                                        </div>
                                    }
                                } else { html! {} }}
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row">
                    <div class="col-12">
                        <div class="card mb-4">
                            <div class="card-header"><h5>{ "Kerberos Settings" }</h5></div>
                            <div class="card-body">
                                <div class="mb-3 row">
                                    <label class="col-sm-4 col-form-label">{ "Ticket lifetime" }</label>
                                    <div class="col-sm-8">
                                        <input type="text" class="form-control" value={self.ticket_lifetime.clone()} oninput={on_ticket} />
                                    </div>
                                </div>
                                <div class="mb-3 row">
                                    <label class="col-sm-4 col-form-label">{ "Renew lifetime" }</label>
                                    <div class="col-sm-8">
                                        <input type="text" class="form-control" value={self.renew_lifetime.clone()} oninput={on_renew} />
                                    </div>
                                </div>
                                <div class="mb-3 row">
                                    <label class="col-sm-4 col-form-label">{ "Forwardable" }</label>
                                    <div class="col-sm-8">
                                        <input type="checkbox" class="form-check-input" checked={self.forwardable} onchange={on_forwardable} />
                                    </div>
                                </div>
                                <div class="mb-3 row">
                                    <label class="col-sm-4 col-form-label">{ "RDNS" }</label>
                                    <div class="col-sm-8">
                                        <input type="checkbox" class="form-check-input" checked={self.rdns} onchange={on_rdns} />
                                    </div>
                                </div>
                            </div>
                            <div class="card-footer text-end">
                                <button onclick={&on_save} class="btn btn-success">{ "Save Changes" }</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}
