use crate::components::{create_ou::CreateOu, delete_ou::DeleteOu, ou_selector::OuSelector};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct OuTableProps {
    pub ou_filter: String,
    pub ous: Vec<String>,
    pub on_ou_changed: Callback<String>,
    pub on_ou_created: Callback<String>,
    pub on_ou_deleted: Callback<String>,
    pub error: Option<String>,
    pub default_primary: String,
}

#[function_component(OuTable)]
pub fn ou_table(props: &OuTableProps) -> Html {
    html! {
        <div class="row g-3 align-items-end mb-3">
            <div class="col-md-3">
                <label class="form-label">{"Organizational Unit"}</label>
                <OuSelector
                    ous={props.ous.clone()}
                    current_ou={props.ou_filter.clone()}
                    on_ou_changed={props.on_ou_changed.clone()}
                    label={None::<String>}
                    show_all={true} />
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
                <CreateOu
                    ous={props.ous.clone()}
                    default_primary={props.default_primary.clone()}
                    on_ou_created={props.on_ou_created.clone()}
                    on_error={Callback::noop()}
                />
            </div>

            <div class="col-auto">
                <DeleteOu
                    ou={props.ou_filter.clone()}
                    reassign_to={props.default_primary.clone()}
                    on_ou_deleted={props.on_ou_deleted.clone()}
                    on_error={Callback::noop()}
                />
            </div>
        </div>
    }
}
