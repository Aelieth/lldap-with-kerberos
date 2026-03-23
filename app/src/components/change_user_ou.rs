use crate::infra::{
    common_component::{CommonComponent, CommonComponentParts},
    modal::Modal,
};
use anyhow::{Error, Result};
use yew::prelude::*;

pub struct ChangeUserOu {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct ChangeUserOuProps {
    pub selected_users: Vec<String>,
    pub on_ou_changed: Callback<String>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedChangeOu,
    ConfirmChangeOu,
    DismissModal,
}

impl CommonComponent<ChangeUserOu> for ChangeUserOu {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedChangeOu => {
                self.modal.as_ref().expect("modal not initialized").show();
            }
            Msg::ConfirmChangeOu => {
                self.update(ctx, Msg::DismissModal);
                // TODO: real GraphQL + selected OU (next turtle step)
                let target = "people".to_string();
                web_sys::console::log_1(&format!("Changing {} users to OU: {}", ctx.props().selected_users.len(), target).into());
                ctx.props().on_ou_changed.emit(target);
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
            }
        }
        Ok(true)
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
        }
    }

    fn rendered(&mut self, _: &Context<Self>, first_render: bool) {
        if first_render {
            self.modal = Some(Modal::new(
                self.node_ref.cast::<web_sys::Element>().expect("Modal node is not an element"),
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
        let count = ctx.props().selected_users.len();
        html! {
          <>
          <button
            class="btn btn-warning"
            disabled={self.common.is_task_running() || count == 0}
            onclick={link.callback(|_| Msg::ClickedChangeOu)}>
            <i class="bi-arrow-left-right me-2" aria-label="Change User OU" />
            {"Change User OU"}
          </button>
          {self.show_modal(ctx)}
          </>
        }
    }
}

impl ChangeUserOu {
    fn show_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        let count = ctx.props().selected_users.len();
        html! {
          <div class="modal fade" id="changeOuModal" tabindex="-1" aria-labelledby="changeOuModalLabel" aria-hidden="true" ref={self.node_ref.clone()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="changeOuModalLabel">{format!("Change OU for {} selected users", count)}</h5>
                  <button type="button" class="btn-close" onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                  <label class="form-label">{"New Organizational Unit"}</label>
                  <select class="form-select">
                    <option value="people">{"people"}</option>
                    <option value="home">{"home"}</option>
                    <option value="office">{"office"}</option>
                    // more from global list later
                  </select>
                </div>
                <div class="modal-footer">
                  <button type="button" class="btn btn-secondary" onclick={link.callback(|_| Msg::DismissModal)}>
                    <i class="bi-x-circle me-2"></i>{"Cancel"}
                  </button>
                  <button type="button" onclick={link.callback(|_| Msg::ConfirmChangeOu)} class="btn btn-primary">
                    <i class="bi-check-circle me-2"></i>{"Change OU"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
