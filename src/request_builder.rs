use crate::types::{PostFields, PostData};

use reqwest::blocking::*;

pub fn build_form(fields: PostFields, data: PostData) -> multipart::Form {
    let mut form = multipart::Form::new();
    if fields.email.is_some() & data.email.is_some() {
        form = form.text(fields.email.unwrap().to_string(), data.email.unwrap());
    }
    if fields.password.is_some() & data.password.is_some() {
        form = form.text(fields.password.unwrap().to_string(), data.password.unwrap());
    }
    if fields.phone.is_some() & data.phone.is_some() {
        form = form.text(fields.phone.unwrap().to_string(), data.phone.unwrap());
    }
    if fields.fname.is_some() & data.fname.is_some() {
        form = form.text(fields.fname.unwrap().to_string(), data.fname.unwrap());
    }
    if fields.lname.is_some() & data.lname.is_some() {
        form = form.text(fields.lname.unwrap().to_string(), data.lname.unwrap());
    }
    if fields.ccn.is_some() & data.ccn.is_some() {
        form = form.text(fields.ccn.unwrap().to_string(), data.ccn.unwrap());
    }
    if fields.exp.is_some() & data.exp.is_some() {
        form = form.text(fields.exp.unwrap().to_string(), data.exp.unwrap());
    }
    if fields.cvv.is_some() & data.cvv.is_some() {
        form = form.text(fields.cvv.unwrap().to_string(), data.cvv.unwrap());
    }
    return form;
}

pub fn build_request(form: multipart::Form, url: String) -> Request {
    let client = reqwest::blocking::Client::new();
    return client.post(url).multipart(form).build().unwrap();
}