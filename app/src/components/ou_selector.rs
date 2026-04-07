use yew::prelude::*;
use wasm_bindgen::JsCast;
use std::collections::HashMap;

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
    // Parse OUs into primary → list of secondaries
    let mut tree: HashMap<String, Vec<String>> = HashMap::new();
    let mut primaries: Vec<String> = vec![];

    for ou in &props.ous {
        if ou.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = ou.splitn(2, '\\').collect();
        if parts.len() == 2 {
            let primary = parts[0].to_string();
            let secondary = parts[1].to_string();
            tree.entry(primary.clone()).or_default().push(secondary);
            if !primaries.contains(&primary) {
                primaries.push(primary);
            }
        } else {
            let primary = ou.clone();
            if !primaries.contains(&primary) {
                primaries.push(primary);
            }
        }
    }

    primaries.sort();

    let mut display_ous = vec![];

    if !props.hide_all {
        display_ous.push(("All".to_string(), "All".to_string()));
    }

    // Always ensure "people" appears first as primary
    if !primaries.contains(&"people".to_string()) {
        primaries.insert(0, "people".to_string());
    }

    for primary in &primaries {
        display_ous.push((primary.clone(), primary.clone()));

        if let Some(secondaries) = tree.get(primary) {
            let mut sorted_secondaries = secondaries.clone();
            sorted_secondaries.sort();
            for (i, secondary) in sorted_secondaries.iter().enumerate() {
                let prefix = if i == sorted_secondaries.len() - 1 { "└── " } else { "├── " };
                let full = format!("{}\\{}", primary, secondary);
                let display = format!("{}{}", prefix, secondary);
                display_ous.push((display, full));
            }
        }
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
                    <option value={value.clone()} selected={value == &props.current_ou}>
                        {display}
                    </option>
                }) }
            </select>
        </div>
    }
}
