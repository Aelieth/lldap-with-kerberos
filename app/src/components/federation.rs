use crate::components::{keycloak_settings::KeycloakSettings, posix_options::PosixOptions};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct FederationProps {}

#[function_component(Federation)]
pub fn federation(_props: &FederationProps) -> Html {
    html! {
        <div class="container">

            <KeycloakSettings />
            <PosixOptions on_status_update={Callback::noop()} />   // noop because POSIX is now fully self-contained
        </div>
    }
}
