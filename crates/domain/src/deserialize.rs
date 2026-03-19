use crate::types::{AttributeType, AttributeValue, JpegPhoto};
use anyhow::{Context as AnyhowContext, Result, bail};
use base64::Engine;
use base64::engine::general_purpose;

pub fn deserialize_attribute_value(
    value: &[String],
    typ: AttributeType,
    is_list: bool,
) -> Result<AttributeValue> {
    if !is_list && value.len() != 1 {
        bail!("Attribute is not a list, but multiple values were provided");
    }
    let parse_int = |value: &String| -> Result<i64> {
        value
        .parse::<i64>()
        .with_context(|| format!("Invalid integer value {value}"))
    };
    let parse_date = |value: &String| -> Result<chrono::NaiveDateTime> {
        Ok(chrono::DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("Invalid date value {value}"))?
        .naive_utc())
    };
    let parse_photo = |value: &String| -> Result<JpegPhoto> {
        if value.is_empty() {
            return Ok(JpegPhoto::null());
        }

        let raw_bytes = general_purpose::STANDARD
        .decode(value)
        .context("Invalid base64 data for avatar")?;

        tracing::info!("DESERIALIZE_AVATAR: decoded raw bytes length = {}", raw_bytes.len());
        if !raw_bytes.is_empty() {
            tracing::info!("DESERIALIZE_AVATAR: first 16 bytes hex = {:02x?}", &raw_bytes[0..16.min(raw_bytes.len())]);
        }

        // Direct construction — this is the missing piece (bypasses the broken TryFrom path)
        Ok(JpegPhoto(raw_bytes))   // ← this line was the culprit
    };
    Ok(match (typ, is_list) {
        (AttributeType::String, false) => value[0].clone().into(),
       (AttributeType::String, true) => value.to_vec().into(),
       (AttributeType::Integer, false) => (parse_int(&value[0])?).into(),
       (AttributeType::Integer, true) => {
           (value.iter().map(parse_int).collect::<Result<Vec<_>>>()?).into()
       }
       (AttributeType::DateTime, false) => (parse_date(&value[0])?).into(),
       (AttributeType::DateTime, true) => {
           (value.iter().map(parse_date).collect::<Result<Vec<_>>>()?).into()
       }
       (AttributeType::JpegPhoto, false) => (parse_photo(&value[0])?).into(),
       (AttributeType::JpegPhoto, true) => {
           (value.iter().map(parse_photo).collect::<Result<Vec<_>>>()?).into()
       }
    })
}
