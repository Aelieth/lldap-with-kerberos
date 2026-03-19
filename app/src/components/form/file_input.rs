use std::{fmt::Display, str::FromStr};

use anyhow::{Error, Ok, Result, bail};
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
use gloo_console::log;

#[derive(Default)]
struct JsFile {
    file: Option<File>,
    contents: Option<Vec<u8>>,
    base64: Option<String>,   // stable value across re-renders
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
    match reader.format() {
        Some(ImageFormat::Jpeg) | Some(ImageFormat::Png) => {
            reader.decode().map_err(|e| anyhow::anyhow!("Decode failed: {}", e))?;
            Ok(())
        }
        _ => bail!("Only JPEG and PNG images are allowed"),
    }
}

fn get_data_url(bytes: &[u8]) -> Result<String> {
    validate_avatar(bytes)?;
    let b64 = general_purpose::STANDARD.encode(bytes);
    let mime = if bytes.starts_with(&[0xFF, 0xD8]) {
        "image/jpeg"
    } else if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        "image/png"
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

pub struct JpegFileInput {
    avatar: Option<JsFile>,
    reader: Option<FileReader>,
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

impl Component for JpegFileInput {
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
        }
    }

    fn changed(&mut self, ctx: &Context<Self>) -> bool {
        // Only reset from props if we have no local data yet (prevents overwrite after upload)
        if self.avatar.as_ref().and_then(|a| a.base64.as_ref()).is_none() {
            self.avatar = Some(JsFile {
                file: None,
                contents: ctx.props().value.as_ref().and_then(|x| general_purpose::STANDARD.decode(x).ok()),
                               base64: ctx.props().value.clone(),
            });
        }
        self.reader = None;
        true
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Update => true,
            Msg::FileSelected(new_avatar) => {
                log!("FileSelected: picked file {}", new_avatar.name());
                if new_avatar.size() > 2 * 1024 * 1024 {
                    log!("FileSelected: too big (>2MB) - clearing");
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
                log!("ClearClicked: avatar cleared");
                self.avatar = Some(JsFile::default());
                true
            }
            Msg::FileLoaded(file_name, data) => {
                if let Some(avatar) = &mut self.avatar
                    && let Some(file) = &avatar.file
                    && file.name() == file_name
                    && let Result::Ok(data) = data
                    {
                        log!("FileLoaded: received {} bytes for {}", data.len(), file_name);
                        if validate_avatar(&data).is_err() {
                            log!("FileLoaded: invalid image - clearing");
                            self.avatar = Some(JsFile::default());
                        } else {
                            let b64 = general_purpose::STANDARD.encode(&data);
                            avatar.contents = Some(data);
                            avatar.base64 = Some(b64.clone());
                            log!("FileLoaded: SUCCESS - base64 stored (len={})", b64.len());
                            return true;
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

        log!("JpegFileInput view: hidden input length = {}", avatar_string.len());
        if avatar_string.is_empty() {
            log!("JpegFileInput view: ERROR - hidden input is EMPTY");
        } else if avatar_string.len() < 100 {
            log!("JpegFileInput view: WARNING - base64 very short (len={})", avatar_string.len());
        } else {
            log!("JpegFileInput view: OK - base64 looks good (len={})", avatar_string.len());
        }

        html! {
            <div class="row align-items-center">
            <div class="col-5">
            <input type="hidden" name={ctx.props().name.clone()} value={avatar_string.clone()} />
            <input
            class="form-control"
            id="avatarInput"
            type="file"
            accept="image/jpeg,image/png"
            oninput={link.callback(|e: InputEvent| {
                let input: HtmlInputElement = e.target_unchecked_into();
                Self::upload_files(input.files())
            })} />
            </div>
            <div class="col-3">
            <button class="btn btn-secondary col-auto" onclick={link.callback(|_| Msg::ClearClicked)}>
            {"Clear"}
            </button>
            </div>
            <div class="col-4">
            { if !avatar_src.is_empty() {
                html! { <img src={avatar_src} style="max-height:128px;max-width:128px;" alt="Avatar" /> }
            } else { html! {} }}
            </div>
            </div>
        }
    }
}

impl JpegFileInput {
    fn upload_files(files: Option<FileList>) -> Msg {
        match files {
            Some(files) if files.length() > 0 => Msg::FileSelected(File::from(files.item(0).unwrap())),
            Some(_) | None => Msg::Update,
        }
    }
}
