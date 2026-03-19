use crate::infra::functional::{LoadableResult, use_graphql_call};
use graphql_client::GraphQLQuery;
use yew::{Properties, function_component, html, virtual_dom::AttrValue};
use base64::{engine::general_purpose, Engine as _};

#[derive(GraphQLQuery)]
#[graphql(
schema_path = "../schema.graphql",
query_path = "queries/get_user_details.graphql",
variables_derives = "Clone,PartialEq,Eq",
response_derives = "Debug, Hash, PartialEq, Eq, Clone",
custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetUserDetails;

fn get_avatar_data_url(base64_data: &str) -> String {
  if base64_data.is_empty() {
    return String::new();
  }
  // Tiny decode just to check magic bytes (no re-encoding, keeps transparency)
  match general_purpose::STANDARD.decode(base64_data) {
    Ok(bytes) if bytes.starts_with(&[0xFF, 0xD8]) => {
      format!("data:image/jpeg;base64,{}", base64_data)
    }
    Ok(bytes) if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) => {
      format!("data:image/png;base64,{}", base64_data)
    }
    _ => format!("data:image/jpeg;base64,{}", base64_data), // safe fallback
  }
}

#[derive(Properties, PartialEq)]
pub struct Props {
  pub user: AttrValue,
  #[prop_or(32)]
  pub width: i32,
  #[prop_or(32)]
  pub height: i32,
}

#[function_component(Avatar)]
pub fn avatar(props: &Props) -> Html {
  let user_details = use_graphql_call::<GetUserDetails>(get_user_details::Variables {
    id: props.user.to_string(),
  });

  match &(*user_details) {
    LoadableResult::Loaded(Ok(response)) => {
      let avatar = response.user.avatar.clone();
      match &avatar {
        Some(data) => html! {
          <img
          id="avatarDisplay"
          src={get_avatar_data_url(data)}
          style={format!("max-height:{}px;max-width:{}px;height:auto;width:auto;", props.height, props.width)}
          alt="Avatar" />
        },
        None => html! {
          <BlankAvatarDisplay
          width={props.width}
          height={props.height} />
        },
      }
    }
    LoadableResult::Loaded(Err(error)) => html! {
      <BlankAvatarDisplay
      error={error.to_string()}
      width={props.width}
      height={props.height} />
    },
    LoadableResult::Loading => html! {
      <BlankAvatarDisplay
      width={props.width}
      height={props.height} />
    },
  }
}

#[derive(Properties, PartialEq)]
struct BlankAvatarDisplayProps {
  #[prop_or(None)]
  pub error: Option<AttrValue>,
  pub width: i32,
  pub height: i32,
}

#[function_component(BlankAvatarDisplay)]
fn blank_avatar_display(props: &BlankAvatarDisplayProps) -> Html {
  let fill = match &props.error {
    Some(_) => "red",
    None => "currentColor",
  };
  html! {
    <svg xmlns="http://www.w3.org/2000/svg"
    width={props.width.to_string()}
    height={props.height.to_string()}
    fill={fill}
    class="bi bi-person-circle"
    viewBox="0 0 16 16">
    <title>{props.error.clone().unwrap_or(AttrValue::Static("Avatar"))}</title>
    <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
    <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1z"/>
    </svg>
  }
}
