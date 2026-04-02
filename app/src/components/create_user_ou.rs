use crate::infra::{
    common_component::{CommonComponent, CommonComponentParts},
    modal::Modal,
};
use crate::components::status_modal::StatusModal;
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;
use wasm_bindgen::JsCast;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_ou.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateOuQuery;

pub struct CreateUserOu {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
    new_ou_name: String,
    status_message: Option<(String, bool)>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct CreateUserOuProps {
    pub on_ou_created: Callback<String>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedCreateOu,
    ConfirmCreateOu,
    DismissModal,
    CreateOuResponse(Result<create_ou_query::ResponseData>),
    NewOuNameChanged(String),
    ShowStatus(String, bool),
    DismissStatus,
}

impl CommonComponent<CreateUserOu> for CreateUserOu {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedCreateOu => {
                self.common.error = None;
                self.new_ou_name = String::new();
                self.status_message = None;
                self.modal.as_ref().expect("modal not initialized").show();
                Ok(true)
            }
            Msg::ConfirmCreateOu => {
                if self.new_ou_name.trim().is_empty() {
                    return Ok(true);
                }
                // ANY non-empty name now reaches the backend (including "all", "people", duplicates)
                self.common.call_graphql::<CreateOuQuery, _>(
                    ctx,
                    create_ou_query::Variables {
                        name: self.new_ou_name.clone(),
                    },
                    Msg::CreateOuResponse,
                    "Error trying to create OU",
                );
                Ok(true)
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
                Ok(true)
            }
            Msg::CreateOuResponse(response) => {
                match response {
                    Ok(_) => {
                        let msg = format!("Successfully created OU: {}", self.new_ou_name);
                        ctx.props().on_ou_created.emit(self.new_ou_name.clone());
                        self.new_ou_name = String::new();
                        ctx.link().send_message(Msg::ShowStatus(msg, true));
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        ctx.props().on_error.emit(e);
                        ctx.link().send_message(Msg::ShowStatus(msg, false));
                    }
                }
                self.modal.as_ref().expect("modal not initialized").hide();
                Ok(true)
            }
            Msg::NewOuNameChanged(name) => {
                self.new_ou_name = name;
                Ok(true)
            }
            Msg::ShowStatus(message, is_success) => {
                self.status_message = Some((message, is_success));
                Ok(true)
            }
            Msg::DismissStatus => {
                self.status_message = None;
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for CreateUserOu {
    type Message = Msg;
    type Properties = CreateUserOuProps;

    fn create(_: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            node_ref: NodeRef::default(),
            modal: None,
            new_ou_name: String::new(),
            status_message: None,
        }
    }

    fn rendered(&mut self, _: &Context<Self>, first_render: bool) {
        if first_render {
            self.modal = Some(Modal::new(
                self.node_ref
                    .cast::<web_sys::Element>()
                    .expect("Modal node is not an element"),
            ));
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update_and_report_error(
            self,
            ctx,
            msg,
            ctx.props().on_error.clone(),
        )
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        let on_input = link.callback(|e: InputEvent| {
            let value = e.target()
                .unwrap()
                .dyn_into::<web_sys::HtmlInputElement>()
                .unwrap()
                .value();
            Msg::NewOuNameChanged(value)
        });

        let status_html = if let Some((msg, is_success)) = &self.status_message {
            let on_dismiss = link.callback(|_| Msg::DismissStatus);
            html! { <StatusModal message={msg.clone()} is_success={*is_success} on_dismiss={on_dismiss} /> }
        } else {
            html! {}
        };

        html! {
          <>
          <button
            class="btn btn-primary"
            disabled={self.common.is_task_running()}   // ← ONLY this line changed
            onclick={link.callback(|_| Msg::ClickedCreateOu)}>
            <i class="bi-people-fill me-2" aria-label="Create OU" />
            {"Create OU"}
          </button>
          {self.show_create_modal(ctx, on_input)}
          {status_html}
          </>
        }
    }
}

impl CreateUserOu {
    fn show_create_modal(&self, ctx: &Context<Self>, on_input: Callback<InputEvent>) -> Html {
        let link = &ctx.link();
        html! {
          <div
            class="modal fade"
            id="createOuModal"
            tabindex="-1"
            aria-labelledby="createOuModalLabel"
            aria-hidden="true"
            ref={self.node_ref.clone()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="createOuModalLabel">{"Create New Organizational Unit"}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                  <input
                    type="text"
                    class="form-control"
                    placeholder="Enter OU name (e.g. office)"
                    value={self.new_ou_name.clone()}
                    oninput={on_input} />
                </div>
                <div class="modal-footer">
                  <button
                    type="button"
                    class="btn btn-secondary"
                    onclick={link.callback(|_| Msg::DismissModal)}>
                    <i class="bi-x-circle me-2"></i>
                    {"Cancel"}
                  </button>
                  <button
                    type="button"
                    onclick={link.callback(|_| Msg::ConfirmCreateOu)}
                    class="btn btn-primary"
                    disabled={self.common.is_task_running() || self.new_ou_name.trim().is_empty()}>
                    <i class="bi-check-circle me-2"></i>
                    {"Create OU"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
