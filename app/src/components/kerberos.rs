use yew::prelude::*;

#[function_component(Kerberos)]
pub fn kerberos() -> Html {
    let service_name = use_state(|| "".to_string());
    let hostname = use_state(|| "".to_string());
    let result = use_state(|| None::<String>);

    let on_service_change = {
        let service_name = service_name.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            service_name.set(input.value());
        })
    };

    let on_hostname_change = {
        let hostname = hostname.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            hostname.set(input.value());
        })
    };

    let on_submit = {
        let service_name = service_name.clone();
        let hostname = hostname.clone();
        let result = result.clone();

        Callback::from(move |_ : MouseEvent| {  // Ignore event if not used
            let service = (*service_name).clone();
            let host = (*hostname).clone();
            let res = result.clone();

            // Mock success (tests form - real mutation next)
            let principal = format!("{}/{}@YOUR_REALM", service, host);
            let keytab_path = format!("/data/keytabs/{}-{}.keytab", service, host);
            res.set(Some(format!("Success! Created/rotated principal: {}\nKeytab exported to: {}", principal, keytab_path)));
        })
    };

    html! {
        <div class="container">
        <h2>{ "Kerberos Management" }</h2>
        <p>{ "Create or rotate a service principal and export its keytab (for Keycloak or desktops)." }</p>

        <div class="mb-3">
        <label class="form-label">{ "Service Type (e.g., HTTP for Keycloak, host for desktops):" }</label>
        <input type="text" class="form-control" value={(*service_name).clone()} oninput={on_service_change} required=true />
        </div>
        <div class="mb-3">
        <label class="form-label">{ "Hostname (e.g., keycloak.testlob.local):" }</label>
        <input type="text" class="form-control" value={(*hostname).clone()} oninput={on_hostname_change} required=true />
        </div>
        <button type="button" class="btn btn-primary" onclick={on_submit}>{ "Create/Rotate Principal & Export Keytab" }</button>

        { if let Some(msg) = &*result {
            html! { <div class="alert alert-success mt-3">{ msg }</div> }
        } else {
            html! {}
        } }
        </div>
    }
}
