use crate::infra::{
    common_component::{CommonComponent, CommonComponentParts},
    modal::Modal,
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/delete_ou.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteOuQuery;

pub struct DeleteUserOu {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct DeleteUserOuProps {
    pub ou: String,
    pub on_ou_deleted: Callback<String>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedDeleteOu,
    ConfirmDeleteOu,
    DismissModal,
    DeleteOuResponse(Result<delete_ou_query::ResponseData>),
}

impl CommonComponent<DeleteUserOu> for DeleteUserOu {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedDeleteOu => {
                self.modal.as_ref().expect("modal not initialized").show();
            }
            Msg::ConfirmDeleteOu => {
                self.update(ctx, Msg::DismissModal);
                self.common.call_graphql::<DeleteOuQuery, _>(
                    ctx,
                    delete_ou_query::Variables {
                        name: ctx.props().ou.clone(),
                    },
                    Msg::DeleteOuResponse,
                    "Error trying to delete OU",
                );
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
            }
            Msg::DeleteOuResponse(response) => {
                response?;
                ctx.props().on_ou_deleted.emit(ctx.props().ou.clone());
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for DeleteUserOu {
    type Message = Msg;
    type Properties = DeleteUserOuProps;

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
        html! {
          <>
          <button
            class="btn btn-danger"
            disabled={self.common.is_task_running()}
            onclick={link.callback(|_| Msg::ClickedDeleteOu)}>
            <i class="bi-x-circle-fill me-2" aria-label="Delete OU" />
            {"Delete OU"}
          </button>
          {self.show_modal(ctx)}
          </>
        }
    }
}

impl DeleteUserOu {
    fn show_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        html! {
          <div
            class="modal fade"
            id={format!("deleteOuModal{}", ctx.props().ou)}
            tabindex="-1"
            aria-labelledby="deleteOuModalLabel"
            aria-hidden="true"
            ref={self.node_ref.clone()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="deleteOuModalLabel">{"Delete Organizational Unit?"}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                <span>
                  {"Are you sure you want to delete Organizational Unit "}
                  <b>{&ctx.props().ou}</b>{"?"}<br />
                  {"All users in this OU will be reassigned to 'people'. This cannot be undone."}
                </span>
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
                    onclick={link.callback(|_| Msg::ConfirmDeleteOu)}
                    class="btn btn-danger">
                    <i class="bi-check-circle me-2"></i>
                    {"Yes, I'm sure"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
