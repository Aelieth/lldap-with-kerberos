use crate::components::{create_user_ou::CreateUserOu, delete_user_ou::DeleteUserOu};
use yew::prelude::*;
use wasm_bindgen::JsCast;

#[derive(Properties, PartialEq)]
pub struct Props {
    pub ou_filter: String,
    pub ous: Vec<String>,
    pub on_ou_changed: Callback<String>,
    pub on_ou_created: Callback<String>,
    pub on_ou_deleted: Callback<String>,
    pub error: Option<String>,
}

#[function_component(UserOuTable)]
pub fn user_ou_table(props: &Props) -> Html {
    let mut display_ous = vec![
        ("All".to_string(), "All".to_string()),
        ("people".to_string(), "people".to_string()),
    ];

    let custom_ous: Vec<&String> = props.ous.iter().filter(|&o| o != "people").collect();

    for (i, ou) in custom_ous.iter().enumerate() {
        let prefix = if i == custom_ous.len() - 1 { "└── " } else { "├── " };
        display_ous.push((format!("{}{}", prefix, ou), (*ou).clone()));
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

            { if let Some(err) = &props.error {
                html! {
                    <div class="col-md-6">
                        <span class="text-danger fw-bold">{err}</span>
                    </div>
                }
            } else {
                html! {}
            }}

            <div class="col-auto">
                <CreateUserOu
                    on_ou_created={props.on_ou_created.clone()}
                    on_error={Callback::noop()}
                />
            </div>

            <div class="col-auto">
                <DeleteUserOu
                    ou={props.ou_filter.clone()}
                    on_ou_deleted={props.on_ou_deleted.clone()}
                    on_error={Callback::noop()}
                />
            </div>
        </div>
    }
}
