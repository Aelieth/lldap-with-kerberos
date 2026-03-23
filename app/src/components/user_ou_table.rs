use crate::components::create_user_ou::CreateUserOu;
use yew::prelude::*;
use wasm_bindgen::JsCast;

#[derive(Properties, PartialEq)]
pub struct Props {
    pub ou_filter: String,
    pub ous: Vec<String>,                     // ← real list from backend (next step)
    pub on_ou_changed: Callback<String>,
    pub on_delete_ou: Callback<()>,
    pub on_ou_created: Callback<String>,      // ← for the real modal
}

#[function_component(UserOuTable)]
pub fn user_ou_table(props: &Props) -> Html {
    // Build nice tree display: All + people always first, then the rest with ├── / └──
    let mut display_ous = vec![
        ("All".to_string(), "All".to_string()),
        ("people".to_string(), "people".to_string()),
    ];

    for (i, ou) in props.ous.iter().enumerate() {
        let prefix = if i == props.ous.len() - 1 { "└── " } else { "├── " };
        display_ous.push((format!("{}{}", prefix, ou), ou.clone()));
    }

    html! {
        <div class="row g-3 align-items-end mb-3">
            <div class="col-md-3">
                <label class="form-label">{"Organizational Unit"}</label>
                <select class="form-select" onchange={props.on_ou_changed.reform(|e: Event| {
                    let value = e.target().unwrap().dyn_into::<web_sys::HtmlSelectElement>().unwrap().value();
                    value
                })}>
                    { for display_ous.iter().map(|(display, value)| html! {
                        <option value={value.clone()} selected={value == &props.ou_filter}>{display}</option>
                    }) }
                </select>
            </div>

            <div class="col-auto">
                <CreateUserOu
                    on_ou_created={props.on_ou_created.clone()}
                    on_error={Callback::noop()}
                />
            </div>

            <div class="col-auto">
                <button class="btn btn-danger" onclick={props.on_delete_ou.reform(|_| ())} disabled={props.ou_filter == "All"}>
                    <i class="bi-x-circle-fill me-2"></i>
                    {"Delete OU"}
                </button>
            </div>
        </div>
    }
}
