use crate::{
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::Result;
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "src/queries/create_service_principal.graphql",  // Fixed - relative to root
response_derives = "Debug,Clone",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateServicePrincipal;

pub struct Kerberos {
    common: CommonComponentParts<Self>,
    service_name: String,
    hostname: String,
    result: Option<String>,
}

pub enum Msg {
    UpdateServiceName(String),
    UpdateHostname(String),
    Submit,
    CreateResponse(Result<create_service_principal::ResponseData>),
}

impl CommonComponent<Kerberos> for Kerberos {
    fn handle_msg(&mut self, ctx: &Context<Self>, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::UpdateServiceName(value) => {
                self.service_name = value;
                Ok(true)
            }
            Msg::UpdateHostname(value) => {
                self.hostname = value;
                Ok(true)
            }
            Msg::Submit => {
                let input = create_service_principal::CreateServicePrincipalInput {
                    serviceName: self.service_name.clone(),
                    hostname: self.hostname.clone(),
                };
                let variables = create_service_principal::Variables { input };
                self.common.call_graphql::<CreateServicePrincipal, _>(
                    ctx,
                    variables,
                    Msg::CreateResponse,
                    "Error creating service principal",
                );
                Ok(false)
            }
            Msg::CreateResponse(res) => {
                let data = res?;
                if data.create_service_principal.ok {
                    let principal = format!("{}/{}@YOUR_REALM", self.service_name, self.hostname);  // Placeholder - enhance backend for real realm later
                    let path = format!("/data/keytabs/{}-{}.keytab", self.service_name, self.hostname);
                    self.result = Some(format!("Success! Created/rotated principal: {}\nKeytab exported to: {}", principal, path));
                }
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for Kerberos {
    type Message = Msg;
    type Properties = ();

    fn create(_: &Context<Self>) -> Self {
        Kerberos {
            common: CommonComponentParts::<Self>::create(),
            service_name: "".to_string(),
            hostname: "".to_string(),
            result: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        html! {
            <div class="container">
            <h2>{ "Kerberos Management" }</h2>
            <p>{ "Create or rotate a service principal and export its keytab (for Keycloak or desktops)." }</p>

            <div class="mb-3">
            <label class="form-label">{ "Service Type (e.g., HTTP for Keycloak, host for desktops):" }</label>
            <input type="text" class="form-control" value={self.service_name.clone()} oninput={link.callback(|e: InputEvent| {
                let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                Msg::UpdateServiceName(input.value())
            })} required=true />
            </div>
            <div class="mb-3">
            <label class="form-label">{ "Hostname (e.g., keycloak.testlob.local):" }</label>
            <input type="text" class="form-control" value={self.hostname.clone()} oninput={link.callback(|e: InputEvent| {
                let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                Msg::UpdateHostname(input.value())
            })} required=true />
            </div>
            <button type="button" class="btn btn-primary" disabled={self.common.is_task_running()} onclick={link.callback(|_| Msg::Submit)}>{ "Create/Rotate Principal & Export Keytab" }</button>

            { if let Some(msg) = &self.result {
                html! { <div class="alert alert-success mt-3">{ msg }</div> }
            } else {
                html! {}
            } }
            { if let Some(e) = &self.common.error {
                html! { <div class="alert alert-danger mt-3">{ e.to_string() }</div> }
            } else {
                html! {}
            } }
            </div>
        }
    }
}
