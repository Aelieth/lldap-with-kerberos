use yew::prelude::*;

#[function_component(Kerberos)]
pub fn kerberos() -> Html {
    html! {
        <div class="container">
        <h2>{ "Kerberos Management" }</h2>
        <p>{ "Service principal tools coming soon! (Form for creating/rotating principals and exporting keytabs.)" }</p>
        </div>
    }
}
