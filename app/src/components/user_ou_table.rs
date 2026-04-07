use crate::components::{create_user_ou::CreateUserOu, delete_user_ou::DeleteUserOu, ou_selector::OuSelector};
use yew::prelude::*;

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
    html! {
        <div class="row g-3 align-items-end mb-3">
            <div class="col-md-3">
                <label class="form-label">{"Organizational Unit"}</label>
                <OuSelector
                    ous={props.ous.clone()}
                    current_ou={props.ou_filter.clone()}
                    on_ou_changed={props.on_ou_changed.clone()}
                    label={None::<String>}
                    hide_all={false} />
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
                    ous={props.ous.clone()}                     // ← pass the list
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
