use crate::types::{PostFields, PostData};

use reqwest::blocking::*;

pub fn build_form(fields: PostFields, data: PostData) -> Request {
    let client = Client::new();
    let mut form = multipart::Form::new();
    if fields.email.is_some() & data.email.is_some() {
        form = form.text(fields.email.unwrap(), data.email.unwrap());
    }
    if fields.password.is_some() & data.password.is_some() {
        form = form.text(fields.password.unwrap(), data.password.unwrap());
    }
}
