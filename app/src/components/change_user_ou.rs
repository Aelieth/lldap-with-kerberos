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
    query_path = "queries/change_user_ou.graphql",
    response_derives = "Debug, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ChangeUserOuQuery;

pub struct ChangeUserOu {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
    selected_ou: String,
    status_message: Option<(String, bool)>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct ChangeUserOuProps {
    pub selected_users: Vec<String>,
    pub ous: Vec<String>,
    pub on_ou_changed: Callback<String>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedChangeOu,
    ConfirmChangeOu,
    DismissModal,
    NewOuSelected(String),
    ShowStatus(String, bool),
    DismissStatus,
    ChangeOuResponse(Result<change_user_ou_query::ResponseData>),
}

impl CommonComponent<ChangeUserOu> for ChangeUserOu {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedChangeOu => {
                if ctx.props().selected_users.is_empty() {
                    return Ok(true);
                }
                self.common.error = None;
                self.selected_ou = "people".to_string();
                self.status_message = None;
                self.modal.as_ref().expect("modal not initialized").show();
                Ok(true)
            }
            Msg::ConfirmChangeOu => {
                if self.selected_ou == "All" || self.selected_ou.is_empty() {
                    return Ok(true);
                }
                let count = ctx.props().selected_users.len();
                let confirm_msg = format!(
                    "Change {} selected user(s) to OU '{}'?\n\nThis cannot be undone.",
                    count, self.selected_ou
                );
                if web_sys::window()
                    .and_then(|w| w.confirm_with_message(&confirm_msg).ok())
                    .unwrap_or(false)
                {
                    self.common.call_graphql::<ChangeUserOuQuery, _>(
                        ctx,
                        change_user_ou_query::Variables {
                            user_ids: ctx.props().selected_users.clone(),
                            new_ou: self.selected_ou.clone(),
                        },
                        Msg::ChangeOuResponse,
                        "Error changing OU",
                    );
                }
                self.modal.as_ref().expect("modal not initialized").hide();
                Ok(true)
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
                Ok(true)
            }
            Msg::NewOuSelected(ou) => {
                self.selected_ou = ou;
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
            Msg::ChangeOuResponse(res) => {
                match res {
                    Ok(_) => {
                        let count = ctx.props().selected_users.len();
                        let msg = format!("Successfully moved {} user(s) to OU: {}", count, self.selected_ou);
                        ctx.link().send_message(Msg::ShowStatus(msg, true));
                        ctx.props().on_ou_changed.emit(self.selected_ou.clone());
                    }
                    Err(e) => {
                        let err_msg = e.to_string();
                        ctx.props().on_error.emit(e);
                        ctx.link().send_message(Msg::ShowStatus(err_msg, false));
                    }
                }
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for ChangeUserOu {
    type Message = Msg;
    type Properties = ChangeUserOuProps;

    fn create(_: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            node_ref: NodeRef::default(),
            modal: None,
            selected_ou: "people".to_string(),
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

        let status_html = if let Some((msg, is_success)) = &self.status_message {
            let on_dismiss = link.callback(|_| Msg::DismissStatus);
            html! { <StatusModal message={msg.clone()} is_success={*is_success} on_dismiss={on_dismiss} /> }
        } else {
            html! {}
        };

        html! {
          <>
          <button
            class="btn btn-warning"
            disabled={self.common.is_task_running() || ctx.props().selected_users.is_empty()}
            onclick={link.callback(|_| Msg::ClickedChangeOu)}>
            <i class="bi-arrow-left-right me-2" aria-label="Change User OU" />
            {"Change User OU"}
          </button>
          {self.show_modal(ctx)}
          {status_html}
          </>
        }
    }
}

impl ChangeUserOu {
    fn show_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        let count = ctx.props().selected_users.len();

        let mut display_ous = vec![
            ("All".to_string(), "All".to_string()),
            ("people".to_string(), "people".to_string()),
        ];
        let custom_ous: Vec<&String> = ctx.props().ous.iter().filter(|&o| o != "people").collect();
        for (i, ou) in custom_ous.iter().enumerate() {
            let prefix = if i == custom_ous.len() - 1 { "└── " } else { "├── " };
            display_ous.push((format!("{}{}", prefix, ou), (*ou).clone()));
        }

        html! {
          <div
            class="modal fade"
            id="changeOuModal"
            tabindex="-1"
            aria-labelledby="changeOuModalLabel"
            aria-hidden="true"
            ref={self.node_ref.clone()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="changeOuModalLabel">{format!("Change OU for {} selected users", count)}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                  <label class="form-label">{"New Organizational Unit"}</label>
                  <select class="form-select" onchange={link.callback(|e: Event| {
                      let value = e.target().unwrap()
                          .dyn_into::<web_sys::HtmlSelectElement>().unwrap()
                          .value();
                      Msg::NewOuSelected(value)
                  })}>
                    { for display_ous.iter().map(|(display, value)| html! {
                        <option value={value.clone()} selected={value == &self.selected_ou}>{display}</option>
                    }) }
                  </select>
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
                    onclick={link.callback(|_| Msg::ConfirmChangeOu)}
                    class="btn btn-primary"
                    disabled={self.selected_ou == "All" || self.selected_ou.is_empty() || self.common.is_task_running()}>
                    <i class="bi-check-circle me-2"></i>
                    {"Change OU"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
