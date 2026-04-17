// app/src/components/federation.rs
use crate::components::{keycloak_settings::KeycloakSettings, posix_options::PosixOptions};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct FederationProps {}

#[function_component(Federation)]
pub fn federation(_props: &FederationProps) -> Html {
    html! {
        <div class="container">
            <KeycloakSettings />
            <div class="row mt-4">
                <div class="col-md-6">
                    <PosixOptions on_status_update={Callback::noop()} />
                </div>
                <div class="col-md-6">
                    // Future cards (e.g. LLDAP System Options) go here
                </div>
            </div>
        </div>
    }
}
