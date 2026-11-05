use axum::http::HeaderMap;

use crate::{error::AppError, models::device::DeviceType};

const UNKNOWN_IP: &str = "unknown";
const DEVICE_TYPE_HEADER_NAMES: [&str; 3] = ["device-type", "deviceType", "x-device-type"];

pub fn request_ip_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(UNKNOWN_IP)
        .to_string()
}

pub fn request_device_type_from_headers(headers: &HeaderMap) -> i32 {
    header_value(headers, &DEVICE_TYPE_HEADER_NAMES)
        .map(DeviceType::from_str)
        .unwrap_or(DeviceType::UnknownBrowser)
        .as_i32()
}

pub fn parse_required_device_type(raw: Option<&str>, field_name: &str) -> Result<i32, AppError> {
    let value = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::BadRequest(format!("Missing {field_name}")))?;

    DeviceType::parse_strict(value)
        .map(DeviceType::as_i32)
        .ok_or_else(|| AppError::BadRequest(format!("Invalid {field_name}")))
}

fn header_value<'a>(headers: &'a HeaderMap, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        headers
            .get(*name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}
