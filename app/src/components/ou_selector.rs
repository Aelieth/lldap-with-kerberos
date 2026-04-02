use yew::prelude::*;
use wasm_bindgen::JsCast;

#[derive(Properties, PartialEq)]
pub struct OuSelectorProps {
    pub ous: Vec<String>,
    pub current_ou: String,
    pub on_ou_changed: Callback<String>,
    pub label: Option<String>,
    pub hide_all: bool,
}

#[function_component(OuSelector)]
pub fn ou_selector(props: &OuSelectorProps) -> Html {
    let mut display_ous = vec![
        ("people".to_string(), "people".to_string()),
    ];

    if !props.hide_all {
        display_ous.insert(0, ("All".to_string(), "All".to_string()));
    }

    let custom_ous: Vec<&String> = props.ous.iter().filter(|&o| o != "people").collect();
    for (i, ou) in custom_ous.iter().enumerate() {
        let prefix = if i == custom_ous.len() - 1 { "└── " } else { "├── " };
        display_ous.push((format!("{}{}", prefix, ou), (*ou).clone()));
    }

    html! {
        <div class="mb-3">
            <select class="form-select" onchange={props.on_ou_changed.reform(|e: Event| {
                let value = e.target().unwrap()
                    .dyn_into::<web_sys::HtmlSelectElement>().unwrap()
                    .value();
                value
            })}>
                { for display_ous.iter().map(|(display, value)| html! {
                    <option value={value.clone()} selected={value == &props.current_ou}>{display}</option>
                }) }
            </select>
        </div>
    }
}
