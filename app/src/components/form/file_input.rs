use std::{fmt::Display, str::FromStr};

use anyhow::{Error, Result, bail};
use gloo_file::{
    File,
    callbacks::{FileReader, read_as_bytes},
};
use web_sys::{FileList, HtmlInputElement, InputEvent};
use yew::Properties;
use yew::{prelude::*, virtual_dom::AttrValue};
use base64::{engine::general_purpose, Engine as _};
use image::ImageFormat;
use std::io::Cursor;

#[derive(Default)]
struct JsFile {
    file: Option<File>,
    contents: Option<Vec<u8>>,
    base64: Option<String>,
}

impl Display for JsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.file.as_ref().map(File::name).unwrap_or_default()
        )
    }
}

impl FromStr for JsFile {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            Ok(JsFile::default())
        } else {
            bail!("Building file from non-empty string")
        }
    }
}

fn validate_avatar(bytes: &[u8]) -> Result<()> {
    if bytes.len() > 2 * 1024 * 1024 {
        bail!("Image must be smaller than 2MB");
    }
    let reader = image::io::Reader::new(Cursor::new(bytes))
    .with_guessed_format()
    .map_err(|e| anyhow::anyhow!("Invalid image data: {}", e))?;

    let format_str = match reader.format() {
        Some(f) => format!("{:?}", f),
        None => "None".to_string(),
    };

    match reader.format() {
        Some(ImageFormat::Jpeg) | Some(ImageFormat::Png) | Some(ImageFormat::Bmp) => Ok(()),
        _ => bail!("Only JPEG, PNG, and BMP images are allowed (detected: {})", format_str),
    }
}

fn get_data_url(bytes: &[u8]) -> Result<String> {
    validate_avatar(bytes)?;
    let b64 = general_purpose::STANDARD.encode(bytes);
    let mime = if bytes.starts_with(&[0xFF, 0xD8]) {
        "image/jpeg"
    } else if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        "image/png"
    } else if bytes.starts_with(b"BM") {
        "image/bmp"
    } else {
        "image/jpeg"
    };
    Ok(format!("data:{};base64,{}", mime, b64))
}

fn to_base64(file: &JsFile) -> Result<String> {
    if let Some(b) = &file.base64 {
        Ok(b.clone())
    } else {
        match file {
            JsFile { file: None, contents: None, .. } => Ok(String::new()),
            JsFile { file: Some(_), contents: None, .. } => bail!("Image file hasn't finished loading, try again"),
            JsFile { file: Some(_), contents: Some(data), .. } => {
                let _ = validate_avatar(data)?;
                Ok(general_purpose::STANDARD.encode(data))
            }
            JsFile { file: None, contents: Some(data), .. } => Ok(general_purpose::STANDARD.encode(data)),
        }
    }
}

pub struct AvatarFileInput {
    avatar: Option<JsFile>,
    reader: Option<FileReader>,
    error: Option<String>,
    cleared: bool,
    hidden_ref: NodeRef,
}

pub enum Msg {
    Update,
    FileSelected(File),
    ClearClicked,
    FileLoaded(String, Result<Vec<u8>>),
}

#[derive(Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub name: AttrValue,
    pub value: Option<String>,
}

impl Component for AvatarFileInput {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        Self {
            avatar: Some(JsFile {
                file: None,
                contents: ctx.props().value.as_ref().and_then(|x| general_purpose::STANDARD.decode(x).ok()),
                         base64: ctx.props().value.clone(),
            }),
            reader: None,
            error: None,
            cleared: false,
            hidden_ref: NodeRef::default(),
        }
    }

    fn changed(&mut self, ctx: &Context<Self>) -> bool {
        if self.cleared {
            self.cleared = false;
            return true;
        }
        if self.avatar.as_ref().and_then(|a| a.base64.as_ref()).is_none() {
            self.avatar = Some(JsFile {
                file: None,
                contents: ctx.props().value.as_ref().and_then(|x| general_purpose::STANDARD.decode(x).ok()),
                               base64: ctx.props().value.clone(),
            });
        }
        self.reader = None;
        self.error = None;
        true
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Update => true,
            Msg::FileSelected(new_avatar) => {
                self.error = None;
                self.cleared = false;
                if new_avatar.size() > 2 * 1024 * 1024 {
                    self.error = Some("Image must be smaller than 2MB".to_string());
                    self.avatar = Some(JsFile::default());
                    return true;
                }
                let file_name = new_avatar.name();
                let link = ctx.link().clone();
                self.reader = Some(read_as_bytes(&new_avatar, move |res| {
                    link.send_message(Msg::FileLoaded(file_name, res.map_err(|e| anyhow::anyhow!("{:#}", e))))
                }));
                self.avatar = Some(JsFile { file: Some(new_avatar), contents: None, base64: None });
                true
            }
            Msg::ClearClicked => {
                self.avatar = Some(JsFile::default());
                self.error = None;
                self.cleared = true;
                if let Some(input) = self.hidden_ref.cast::<HtmlInputElement>() {
                    input.set_value("");
                }
                true
            }
            Msg::FileLoaded(file_name, data) => {
                if let Some(avatar) = &mut self.avatar
                    && let Some(file) = &avatar.file
                    && file.name() == file_name
                    && let Result::Ok(data) = data
                    {
                        if validate_avatar(&data).is_err() {
                            self.error = Some("Only JPEG, PNG, or BMP <2MB allowed".to_string());
                            self.avatar = Some(JsFile::default());
                        } else {
                            let b64 = general_purpose::STANDARD.encode(&data);
                            avatar.contents = Some(data);
                            avatar.base64 = Some(b64.clone());
                            self.error = None;
                        }
                    }
                    self.reader = None;
                    true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();

        let avatar_string = match &self.avatar {
            Some(avatar) => to_base64(avatar).as_deref().unwrap_or("").to_owned(),
            None => String::new(),
        };
        let avatar_src = match &self.avatar {
            Some(avatar) if avatar.contents.is_some() => get_data_url(avatar.contents.as_ref().unwrap()).unwrap_or_default(),
            _ => String::new(),
        };

        html! {
            <div class="row align-items-center">
            <div class="col-5">
            <input type="hidden" ref={self.hidden_ref.clone()} name={ctx.props().name.clone()} value={avatar_string.clone()} />
            <input class="form-control" id="avatarInput" type="file" accept="image/jpeg,image/png,image/bmp" oninput={link.callback(|e: InputEvent| { let input: HtmlInputElement = e.target_unchecked_into(); Self::upload_files(input.files()) })} />
            </div>
            <div class="col-3">
            <button type="button" class="btn btn-secondary col-auto" onclick={link.callback(|_| Msg::ClearClicked)}>{"Clear"}</button>
            { if let Some(err) = &self.error { html! { <div class="text-danger small mt-1">{err}</div> } } else { html! {} }}
            </div>
            <div class="col-4" style="background:transparent !important;background-color:transparent !important;">
            { if !avatar_src.is_empty() {
                html! {
                    <div style={format!("width:128px;height:128px;background-image:url({});background-size:contain;background-repeat:no-repeat;background-position:center;background-color:transparent !important;border-radius:4px;", avatar_src)} />
                }
            } else { html! {} }}
            </div>
            </div>
        }
    }
}

impl AvatarFileInput {
    fn upload_files(files: Option<FileList>) -> Msg {
        match files {
            Some(files) if files.length() > 0 => Msg::FileSelected(File::from(files.item(0).unwrap())),
            _ => Msg::Update,
        }
    }
}
