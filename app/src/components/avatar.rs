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
    if base64_data.trim().is_empty() { return String::new(); }
    match general_purpose::STANDARD.decode(base64_data) {
        Ok(bytes) => {
            let mime = if bytes.starts_with(&[0xFF, 0xD8]) { "image/jpeg" }
            else if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) { "image/png" }
            else if bytes.starts_with(b"BM") { "image/bmp" }
            else { "image/jpeg" };
            format!("data:{};base64,{}", mime, base64_data)
        }
        Err(_) => String::new(),
    }
}

#[derive(Properties, PartialEq)]
pub struct Props {
    #[prop_or_default] pub user: Option<AttrValue>,
    #[prop_or_default] pub avatar_base64: Option<AttrValue>,
    #[prop_or(128)] pub width: i32,
    #[prop_or(128)] pub height: i32,
}

#[function_component(Avatar)]
pub fn avatar(props: &Props) -> Html {
    if let Some(base64) = &props.avatar_base64 {
        if !base64.is_empty() {
            let src = get_avatar_data_url(base64);
            if !src.is_empty() {
                return html! {
                    <div style={format!(
                        "width:{}px;height:{}px;background-image:url({});background-size:contain;background-repeat:no-repeat;background-position:center;background-color:transparent;border-radius:4px;",
                        props.width, props.height, src
                    )} />
                };
            }
        }
    }

    let user_details = if let Some(user_id) = &props.user {
        use_graphql_call::<GetUserDetails>(get_user_details::Variables { id: user_id.to_string() })
    } else {
        return html! { <BlankAvatarDisplay width={props.width} height={props.height} /> };
    };

    match &(*user_details) {
        LoadableResult::Loaded(Ok(response)) => {
            match &response.user.avatar {
                Some(data) if !data.is_empty() => {
                    let src = get_avatar_data_url(data);
                    html! {
                        <div style={format!(
                            "width:{}px;height:{}px;background-image:url({});background-size:contain;background-repeat:no-repeat;background-position:center;background-color:transparent;border-radius:4px;",
                            props.width, props.height, src
                        )} />
                    }
                }
                _ => html! { <BlankAvatarDisplay width={props.width} height={props.height} /> },
            }
        }
        _ => html! { <BlankAvatarDisplay width={props.width} height={props.height} /> },
    }
}

#[derive(Properties, PartialEq)]
struct BlankAvatarDisplayProps {
    #[prop_or(None)] pub error: Option<AttrValue>,
    pub width: i32,
    pub height: i32,
}

#[function_component(BlankAvatarDisplay)]
fn blank_avatar_display(props: &BlankAvatarDisplayProps) -> Html {
    let fill = if props.error.is_some() { "red" } else { "currentColor" };
    html! {
        <svg xmlns="http://www.w3.org/2000/svg" width={props.width.to_string()} height={props.height.to_string()} fill={fill} class="bi bi-person-circle" viewBox="0 0 16 16">
            <title>{props.error.clone().unwrap_or(AttrValue::Static("Avatar"))}</title>
            <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
            <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1z"/>
        </svg>
    }
}
