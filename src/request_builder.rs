use crate::types::{PostFields, PostData};

use reqwest::blocking::*;

pub fn build_form_multipart(fields: PostFields, data: PostData) -> multipart::Form {
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
    if fields.ssn.is_some() & data.ssn.is_some() {
        form = form.text(fields.ssn.unwrap().to_string(), data.ssn.unwrap());
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
    for custom_field in fields.custom {
        let split_field: Vec<&str> = custom_field.split(':').collect();
        form = form.text(split_field[0].to_string(), split_field[1].to_string());
    }
    return form;
}

pub fn build_form_urlencoded(fields: PostFields, data: PostData) -> std::collections::HashMap<String, String> {
    let mut form: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    if fields.email.is_some() & data.email.is_some() {
        form.insert(fields.email.unwrap().to_string(), data.email.unwrap());
    }
    if fields.password.is_some() & data.password.is_some() {
        form.insert(fields.password.unwrap().to_string(), data.password.unwrap());
    }
    if fields.phone.is_some() & data.phone.is_some() {
        form.insert(fields.phone.unwrap().to_string(), data.phone.unwrap());
    }
    if fields.fname.is_some() & data.fname.is_some() {
        form.insert(fields.fname.unwrap().to_string(), data.fname.unwrap());
    }
    if fields.lname.is_some() & data.lname.is_some() {
        form.insert(fields.lname.unwrap().to_string(), data.lname.unwrap());
    }
    if fields.ssn.is_some() & data.ssn.is_some() {
        form.insert(fields.ssn.unwrap().to_string(), data.ssn.unwrap());
    }
    if fields.ccn.is_some() & data.ccn.is_some() {
        form.insert(fields.ccn.unwrap().to_string(), data.ccn.unwrap());
    }
    if fields.exp.is_some() & data.exp.is_some() {
        form.insert(fields.exp.unwrap().to_string(), data.exp.unwrap());
    }
    if fields.cvv.is_some() & data.cvv.is_some() {
        form.insert(fields.cvv.unwrap().to_string(), data.cvv.unwrap());
    }
    for custom_field in fields.custom {
        let split_field: Vec<&str> = custom_field.split(':').collect();
        form.insert(split_field[0].to_string(), split_field[1].to_string());
    }
    return form;
}

pub fn build_form_getencoded(fields: PostFields, data: PostData) -> std::collections::HashMap<String, String> {
    let mut form: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    if fields.email.is_some() & data.email.is_some() {
        form.insert(fields.email.unwrap().to_string(), data.email.unwrap());
    }
    if fields.password.is_some() & data.password.is_some() {
        form.insert(fields.password.unwrap().to_string(), data.password.unwrap());
    }
    if fields.phone.is_some() & data.phone.is_some() {
        form.insert(fields.phone.unwrap().to_string(), data.phone.unwrap());
    }
    if fields.fname.is_some() & data.fname.is_some() {
        form.insert(fields.fname.unwrap().to_string(), data.fname.unwrap());
    }
    if fields.lname.is_some() & data.lname.is_some() {
        form.insert(fields.lname.unwrap().to_string(), data.lname.unwrap());
    }
    if fields.ssn.is_some() & data.ssn.is_some() {
        form.insert(fields.ssn.unwrap().to_string(), data.ssn.unwrap());
    }
    if fields.ccn.is_some() & data.ccn.is_some() {
        form.insert(fields.ccn.unwrap().to_string(), data.ccn.unwrap());
    }
    if fields.exp.is_some() & data.exp.is_some() {
        form.insert(fields.exp.unwrap().to_string(), data.exp.unwrap());
    }
    if fields.cvv.is_some() & data.cvv.is_some() {
        form.insert(fields.cvv.unwrap().to_string(), data.cvv.unwrap());
    }
    for custom_field in fields.custom {
        let split_field: Vec<&str> = custom_field.split(':').collect();
        form.insert(split_field[0].to_string(), split_field[1].to_string());
    }
    return form;
}

pub fn build_request(multipart: Option<multipart::Form>, urlencoded: Option<std::collections::HashMap<String, String>>, getencoded: Option<std::collections::HashMap<String, String>>, url: String, redirect: bool, cookies: Vec<String>) -> Request {
    use reqwest::{cookie::Jar, Url};
    let mut jar: Option<reqwest::cookie::Jar> = None;
    if cookies.len() > 0 {
        let tempjar = Jar::default();
        for cookie in cookies {
            tempjar.add_cookie_str(cookie.as_str(), &url.parse::<Url>().unwrap());
        }
        jar = Some(tempjar);
    }
    let redirect_value;
    if redirect {
        redirect_value = reqwest::redirect::Policy::limited(5);
    } else {
        redirect_value = reqwest::redirect::Policy::none();
    }
    if jar.is_some() {
        if multipart.is_some() {
            let client = reqwest::blocking::Client::builder().user_agent(fakeit::user_agent::random_platform()).cookie_store(true).cookie_provider(std::sync::Arc::new(jar.unwrap())).redirect(redirect_value).build().unwrap();
            return client.post(url).multipart(multipart.unwrap()).build().unwrap();
        } else if urlencoded.is_some() {
            let client = reqwest::blocking::Client::builder().user_agent(fakeit::user_agent::random_platform()).cookie_store(true).cookie_provider(std::sync::Arc::new(jar.unwrap())).redirect(redirect_value).build().unwrap();
            return client.post(url).form(&urlencoded.unwrap()).build().unwrap();
        } else {
            let client = reqwest::blocking::Client::builder().user_agent(fakeit::user_agent::random_platform()).cookie_store(true).cookie_provider(std::sync::Arc::new(jar.unwrap())).redirect(redirect_value).build().unwrap();
            return client.post(url).query(&getencoded.unwrap()).build().unwrap();
        }
    } else {
        if multipart.is_some() {
            let client = reqwest::blocking::Client::builder().user_agent(fakeit::user_agent::random_platform()).redirect(redirect_value).build().unwrap();
            return client.post(url).multipart(multipart.unwrap()).build().unwrap();
        } else if urlencoded.is_some() {
            let client = reqwest::blocking::Client::builder().user_agent(fakeit::user_agent::random_platform()).redirect(redirect_value).build().unwrap();
            return client.post(url).form(&urlencoded.unwrap()).build().unwrap();
        } else {
            let client = reqwest::blocking::Client::builder().user_agent(fakeit::user_agent::random_platform()).redirect(redirect_value).build().unwrap();
            return client.post(url).query(&getencoded.unwrap()).build().unwrap();
        }
    }
}
