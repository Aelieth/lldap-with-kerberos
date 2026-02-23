use crate::{
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use yew::prelude::*;

pub struct Kerberos {
    common: CommonComponentParts<Self>,
}

pub enum Msg {}

impl CommonComponent<Kerberos> for Kerberos {
    fn handle_msg(&mut self, _: &Context<Self>, _: <Self as Component>::Message) -> anyhow::Result<bool> {
        Ok(true)
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
        }
    }

    fn update(&mut self, _: &Context<Self>, _: Self::Message) -> bool {
        false
    }

    fn view(&self, _: &Context<Self>) -> Html {
        html! {
            <div class="container">
            <h2>{ "Kerberos Management" }</h2>
            <div class="alert alert-info">
            <h4>{ "Coming soon" }</h4>
            <p>{ "Service principal management (Keycloak API integration) is currently deprecated and will be re-added in a future update." }</p>
            <p>{ "Kerberos sync for users (kerberossync toggle + password change) is fully working." }</p>
            </div>
            </div>
        }
    }
}
