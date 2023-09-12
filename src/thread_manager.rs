use crate::generator::*;
use crate::request_builder::*;
use crate::types::*;

use std::fs;
use std::io::Write;

use std::sync::{Arc, Mutex};

pub fn execute(
    form_type: (bool, bool, bool),
    fields: PostFields,
    url: String,
    domain: String,
    threads: u64,
    redirect: bool,
    password_list: Option<String>,
    debug: bool,
) {
    let mut use_password_list: bool = false;
    let password_data: Arc<Mutex<Vec<String>>> = match password_list {
        Some(s) => {
            let password_file = fs::read_to_string(s).expect("Failed to open password list file.");
            use_password_list = true;
            Arc::new(Mutex::new(
                password_file.split('\n').map(str::to_string).collect(),
            ))
        }
        None => Arc::new(Mutex::new(Vec::new())),
    };
    for _ in 0..threads {
        let fields_clone = fields.clone();
        let domain_clone = domain.clone();
        let url_clone = url.clone();
        let debug_clone = debug.clone();
        let form_type_clone = form_type.clone();
        let password_data_clone = password_data.clone();
        let use_password_list_clone = use_password_list.clone();
        std::thread::spawn(move || loop {
            let domain_clone1 = domain_clone.clone();
            let url_clone1 = url_clone.clone();
            let fields_clone1 = fields_clone.clone();
            let fields_clone2 = fields_clone.clone();
            let cookies_clone = fields_clone.clone().cookies;
            let debug_clone1 = debug_clone.clone();
            let form_type_clone1 = form_type_clone.clone();
            let password_data_clone1 = password_data_clone.clone();
            let use_password_list_clone1 = use_password_list_clone.clone();
            let client = reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let response = match client.execute(if form_type_clone1.0 {
                build_request(
                    Some(build_form_multipart(
                        fields_clone1,
                        generate_from_fields(
                            fields_clone2,
                            domain_clone1,
                            password_data_clone1,
                            use_password_list_clone1,
                        ),
                    )),
                    None,
                    None,
                    url_clone1,
                    redirect,
                    cookies_clone,
                )
            } else if form_type_clone1.1 {
                build_request(
                    None,
                    Some(build_form_urlencoded(
                        fields_clone1,
                        generate_from_fields(
                            fields_clone2,
                            domain_clone1,
                            password_data_clone1,
                            use_password_list_clone1,
                        ),
                    )),
                    None,
                    url_clone1,
                    redirect,
                    cookies_clone,
                )
            } else if form_type_clone1.2 {
                build_request(
                    None,
                    None,
                    Some(build_form_getencoded(
                        fields_clone1,
                        generate_from_fields(
                            fields_clone2,
                            domain_clone1,
                            password_data_clone1,
                            use_password_list_clone1,
                        ),
                    )),
                    url_clone1,
                    redirect,
                    cookies_clone,
                )
            } else {
                eprintln!("Query format not found.");
                std::process::exit(0);
            }) {
                Ok(o) => Some(o),
                Err(e) => {
                    if debug_clone1 {
                        println!("{:?}", e);
                        std::io::stdout()
                            .flush()
                            .ok()
                            .expect("Could not flush stdout");
                    } else {
                        print!("!");
                        std::io::stderr()
                            .flush()
                            .ok()
                            .expect("Could not flush stdout");
                    }
                    None
                }
            };
            if response.is_some() {
                let res = response.unwrap();
                if res.status().is_success() | res.status().is_redirection() {
                    if debug_clone1 {
                        println!("{:?}", res);
                        std::io::stdout()
                            .flush()
                            .ok()
                            .expect("Could not flush stdout");
                    } else {
                        print!(".");
                        std::io::stdout()
                            .flush()
                            .ok()
                            .expect("Could not flush stdout");
                    }
                } else {
                    if debug_clone1 {
                        println!("{:?}", res);
                        std::io::stdout()
                            .flush()
                            .ok()
                            .expect("Could not flush stdout");
                    } else {
                        print!("x");
                        std::io::stdout()
                            .flush()
                            .ok()
                            .expect("Could not flush stdout");
                    }
                }
            }
        });
    }
}
