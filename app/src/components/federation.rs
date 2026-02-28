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
query_path = "src/queries/test_keycloak_connection.graphql",
response_derives = "Debug"
)]
pub struct TestKeycloakConnection;

pub struct Federation {
    common: CommonComponentParts<Self>,
    keycloak_url: String,
    realm: String,
    admin_username: String,
    admin_password: String,  // in-memory only — never saved to disk
    keycloak_hostname: String,
    connection_status: String,
}

pub enum Msg {
    LoadSuggestedConfig,
    TestConnection,
    UpdateUrl(String),
    UpdateRealm(String),
    UpdateUsername(String),
    UpdatePassword(String),
    UpdateHostname(String),
    GenerateRealmJson,
    ExportKeytab,
    SuggestedConfigResponse(Result<keycloak_suggested_config::ResponseData>),
    TestConnectionResponse(Result<test_keycloak_connection::ResponseData>),
    ExportKeytabResponse(Result<export_keytab_for_keycloak::ResponseData>),
}

impl CommonComponent<Federation> for Federation {
    fn handle_msg(&mut self, ctx: &Context<Self>, msg: <Self as Component>::Message) -> anyhow::Result<bool> {
        match msg {
            Msg::LoadSuggestedConfig => {
                let variables = keycloak_suggested_config::Variables {};
                self.common.call_graphql::<KeycloakSuggestedConfig, _>(
                    ctx,
                    variables,
                    Msg::SuggestedConfigResponse,
                    "Failed to load suggested config",
                );
                self.connection_status = "Loading suggested config from live Kerberos...".to_string();
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
                self.common.call_graphql::<TestKeycloakConnection, _>(
                    ctx,
                    variables,
                    Msg::TestConnectionResponse,
                    "Error trying to test Keycloak connection",
                );
                self.connection_status = "Testing connection...".to_string();
                Ok(true)
            }
            Msg::UpdateUrl(url) => {
                self.keycloak_url = url;
                Ok(true)
            }
            Msg::UpdateRealm(realm) => {
                self.realm = realm;
                Ok(true)
            }
            Msg::UpdateUsername(username) => {
                self.admin_username = username;
                Ok(true)
            }
            Msg::UpdatePassword(password) => {
                self.admin_password = password;
                Ok(true)
            }
            Msg::UpdateHostname(hostname) => {
                self.keycloak_hostname = hostname;
                Ok(true)
            }
            Msg::GenerateRealmJson => {
                let derived_realm = self.realm.to_uppercase();
                let base_dn = "dc=example,dc=com";
                let bind_dn = format!("cn=admin,ou=people,{}", base_dn);
                let users_dn = format!("ou=people,{}", base_dn);
                let groups_dn = format!("ou=groups,{}", base_dn);

                let realm_json = json!({
                    "realm": derived_realm.clone(),
                                       "enabled": true,
                                       "sslRequired": "none",
                                       "registrationAllowed": false,
                                       "resetPasswordAllowed": true,
                                       "users": [],
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
                                               "name": "lldap-federation",
                                               "providerId": "ldap",
                                               "providerType": "org.keycloak.storage.UserStorageProvider",
                                               "config": {
                                                   "vendor": ["other"],
                                                   "connectionUrl": ["ldap://lldap:389"],
                                                   "bindDn": [bind_dn],
                                                   "bindCredential": ["<ENTER YOUR LLDAP ADMIN PASSWORD HERE AFTER IMPORT>"],
                                                   "usersDn": [users_dn],
                                                   "groupsDn": [groups_dn],
                                                   "userObjectClasses": ["inetOrgPerson"],
                                                   "rdnAttribute": ["cn"],
                                                   "uuidAttribute": ["uid"],
                                                   "usernameLDAPAttribute": ["uid"],
                                                   "searchScope": ["subtree"],
                                                   "validatePasswordPolicy": ["false"],
                                                   "trustEmail": ["true"],
                                                   "syncRegistrations": ["true"]
                                               }
                                           }]
                                       },
                                       "_comment": "Generated by LLDAP+Kerberos Federation page. Import with: docker run ... --import-realm"
                });

                let json_str = serde_json::to_string_pretty(&realm_json).unwrap();
                let data_url = format!("data:application/json;charset=utf-8,{}", json_str);

                if let Some(window) = window() {
                    let document = window.document().unwrap();
                    let a = document.create_element("a").unwrap();
                    let a: web_sys::HtmlElement = a.dyn_into().unwrap();
                    a.set_attribute("href", &data_url).unwrap();
                    a.set_attribute("download", &format!("{}-realm.json", derived_realm.to_lowercase())).unwrap();
                    a.click();
                }

                self.connection_status = format!("✅ Downloaded {}-realm.json — ready to import!", derived_realm);
                Ok(true)
            }
            Msg::ExportKeytab => {
                let variables = export_keytab_for_keycloak::Variables {
                    hostname: self.keycloak_hostname.clone(),
                };

                self.common.call_graphql::<ExportKeytabForKeycloak, _>(
                    ctx,
                    variables,
                    Msg::ExportKeytabResponse,
                    "Error trying to export keytab",
                );
                self.connection_status = "Exporting keytab...".to_string();
                Ok(true)
            }
            Msg::SuggestedConfigResponse(Ok(data)) => {
                let cfg = data.keycloak_suggested_config;
                self.keycloak_url = cfg.url;
                self.realm = cfg.realm;
                self.admin_username = cfg.admin_username;
                self.keycloak_hostname = cfg.keycloak_hostname;
                self.connection_status = "✅ Auto-filled from live Kerberos config".to_string();
                Ok(true)
            }
            Msg::SuggestedConfigResponse(Err(e)) => {
                self.connection_status = format!("❌ Failed to load suggested config: {}", e);
                Ok(true)
            }
            Msg::TestConnectionResponse(Ok(data)) => {
                let resp = data.test_keycloak_connection;
                self.connection_status = resp.message;
                Ok(true)
            }
            Msg::TestConnectionResponse(Err(e)) => {
                self.connection_status = format!("❌ {}", e);
                Ok(true)
            }
            Msg::ExportKeytabResponse(Ok(data)) => {
                let resp = data.export_keytab_for_keycloak;
                if resp.ok {
                    let path = resp.path;
                    self.connection_status = format!(
                        "✅ Keytab saved to {} on the server!\n\nCopy with:\ndocker cp lldap-kerb:{} ./keycloak-http.keytab",
                        path, path
                    );
                } else {
                    self.connection_status = format!("❌ {}", resp.error_msg);
                }
                Ok(true)
            }
            Msg::ExportKeytabResponse(Err(e)) => {
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
        let link = ctx.link().clone();
        link.send_message(Msg::LoadSuggestedConfig);

        Federation {
            common: CommonComponentParts::<Self>::create(),
            keycloak_url: "http://keycloak:8080".to_string(),
            realm: "".to_string(),
            admin_username: "admin".to_string(),
            admin_password: "".to_string(),
            keycloak_hostname: "keycloak".to_string(),
            connection_status: "Loading suggested config from Kerberos...".to_string(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.handle_msg(ctx, msg).unwrap_or(false)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let on_test = ctx.link().callback(|_| Msg::TestConnection);
        let on_generate = ctx.link().callback(|_| Msg::GenerateRealmJson);
        let on_export = ctx.link().callback(|_| Msg::ExportKeytab);
        let on_url = ctx.link().callback(|e: InputEvent| Msg::UpdateUrl(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_realm = ctx.link().callback(|e: InputEvent| Msg::UpdateRealm(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_username = ctx.link().callback(|e: InputEvent| Msg::UpdateUsername(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_password = ctx.link().callback(|e: InputEvent| Msg::UpdatePassword(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));
        let on_hostname = ctx.link().callback(|e: InputEvent| Msg::UpdateHostname(e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value()));

        html! {
            <div class="container">
            <h2>{ "Federation Settings (LLDAP + Kerberos + Keycloak)" }</h2>

            <div class="row">
            <div class="col-md-6">
            <div class="card mb-4">
            <div class="card-header">
            <h5>{ "Connection Settings" }</h5>
            </div>
            <div class="card-body">
            <div class="mb-3">
            <label class="form-label">{ "Keycloak URL" }</label>
            <input type="url" class="form-control" value={self.keycloak_url.clone()} oninput={on_url.clone()} />
            <small class="text-muted">{ "Auto-filled from your base DN — edit only if needed" }</small>
            </div>
            <div class="mb-3">
            <label class="form-label">{ "Realm" }</label>
            <input type="text" class="form-control" value={self.realm.clone()} oninput={on_realm.clone()} />
            </div>
            <div class="mb-3">
            <label class="form-label">{ "Admin Username" }</label>
            <input type="text" class="form-control" value={self.admin_username.clone()} oninput={on_username.clone()} />
            </div>
            <div class="mb-3">
            <label class="form-label">{ "Admin Password (in-memory only)" }</label>
            <input type="password" class="form-control" value={self.admin_password.clone()} oninput={on_password.clone()} placeholder="Enter Keycloak admin password for test" />
            <small class="text-muted">{ "Never saved — used only for this test button" }</small>
            </div>
            <button onclick={on_test} class="btn btn-primary">{ "Test Connection" }</button>
            <div class="mt-3 alert alert-info">
            { &self.connection_status }
            </div>
            </div>
            </div>
            </div>

            <div class="col-md-6">
            <div class="card mb-4">
            <div class="card-header">
            <h5>{ "Realm Management" }</h5>
            </div>
            <div class="card-body">
            <p>{ "One-click export of a fully configured realm.json" }</p>
            <button onclick={on_generate} class="btn btn-success w-100 mb-3">{ "Generate & Download realm.json" }</button>
            <div class="alert alert-info small">
            <strong>{"After import:"}</strong>{" Open Keycloak → User Federation → lldap-federation and set Bind Credential."}
            </div>
            </div>
            </div>

            <div class="card mb-4">
            <div class="card-header">
            <h5>{ "Keytab for Keycloak (HTTP Service Principal)" }</h5>
            </div>
            <div class="card-body">
            <p>{ "One-click export of keycloak-http.keytab (auto-generated from live Kerberos realm)" }</p>
            <div class="mb-3">
            <label class="form-label">{ "Keycloak Hostname" }</label>
            <input type="text" class="form-control" value={self.keycloak_hostname.clone()} oninput={on_hostname.clone()} placeholder="keycloak (auto → keycloak.yourdomain)" />
            <small class="text-muted">{ "Default \"keycloak\" auto-completes from your base DN" }</small>
            </div>
            <button onclick={on_export} class="btn btn-success w-100 mb-3">{ "Export keycloak-http.keytab" }</button>
            <div class="alert alert-info small">
            <strong>{"After export:"}</strong>{" Run: docker cp lldap-kerb:/data/keycloak-http.keytab ./keycloak-http.keytab"}
            </div>
            </div>
            </div>
            </div>
            </div>
            </div>
        }
    }
}
