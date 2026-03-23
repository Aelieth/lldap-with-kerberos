use yew::prelude::*;
use wasm_bindgen::JsCast;

#[derive(Properties, PartialEq)]
pub struct Props {
    pub search_field: String,
    pub search_term: String,
    pub on_search_field_changed: Callback<String>,
    pub on_search_term_changed: Callback<String>,
}

#[function_component(SearchControls)]
pub fn search_controls(props: &Props) -> Html {
    let search_fields = vec!["User ID".to_string(), "Email".to_string(), "Display Name".to_string(), "First Name".to_string(), "Last Name".to_string()];

    html! {
        <div class="row g-3 align-items-end mb-3">
        <div class="col-md-2">
        <label class="form-label">{"Search"}</label>
        <select class="form-select" onchange={props.on_search_field_changed.reform(|e: Event| {
            let value = e.target().unwrap().dyn_into::<web_sys::HtmlSelectElement>().unwrap().value();
            value
        })}>
        { for search_fields.iter().map(|f| html! {
            <option value={f.clone()} selected={f == &props.search_field}>{f}</option>
        }) }
        </select>
        </div>
        <div class="col-md-4">
        <input type="text" class="form-control" placeholder="Type to search..." value={props.search_term.clone()}
        oninput={props.on_search_term_changed.reform(|e: InputEvent| {
            let value = e.target().unwrap().dyn_into::<web_sys::HtmlInputElement>().unwrap().value();
            value
        })} />
        </div>
        </div>
    }
}
