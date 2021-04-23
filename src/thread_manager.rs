use crate::types::*;
use crate::request_builder::*;
use crate::generator::*;

use std::io::Write;

pub fn execute(form_type: u8, fields: PostFields, url: String, domain: String, threads: u64, debug: bool) {
    for _ in 0..threads {
        let fields_clone = fields.clone();
        let domain_clone = domain.clone();
        let url_clone = url.clone();
        let debug_clone = debug.clone();
        let form_type_clone = form_type.clone();
        std::thread::spawn(move || {
            loop {
                let domain_clone1 = domain_clone.clone();
                let url_clone1 = url_clone.clone();
                let fields_clone1 = fields_clone.clone();
                let fields_clone2 = fields_clone.clone();
                let debug_clone1 = debug_clone.clone();
                let form_type_clone1 = form_type_clone.clone();
                let client = reqwest::blocking::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
                let response = match client.execute(
                    if form_type_clone1 == 1 {
                        build_request(
                            Some(
                                build_form_multipart(
                                    fields_clone1,
                                    generate_from_fields(
                                        fields_clone2,
                                        domain_clone1
                                    )
                                )
                            ),
                            None,
                            url_clone1
                        )
                    } else {
                        build_request(
                            None,
                            Some(
                                build_form_urlencoded(
                                    fields_clone1,
                                    generate_from_fields(
                                        fields_clone2,
                                        domain_clone1
                                    )
                                )
                            ),
                            url_clone1
                        )
                    }
                ) {
                    Ok(o) => Some(o),
                    Err(e) => {
                        if debug_clone1 {
                            println!("{:?}", e);
                            std::io::stdout().flush().ok().expect("Could not flush stdout");
                        } else {
                            print!("!");
                            std::io::stderr().flush().ok().expect("Could not flush stdout");
                        }
                        None
                  }
                };
                if response.is_some() {
                    let res = response.unwrap();
                    if res.status().is_success() | res.status().is_redirection() {
                        if debug_clone1 {
                            println!("{:?}", res);
                            std::io::stdout().flush().ok().expect("Could not flush stdout");
                        } else {
                            print!(".");
                            std::io::stdout().flush().ok().expect("Could not flush stdout");
                        }
                    } else {
                        if debug_clone1 {
                            println!("{:?}", res);
                            std::io::stdout().flush().ok().expect("Could not flush stdout");
                        } else {
                            print!("x");
                            std::io::stdout().flush().ok().expect("Could not flush stdout");
                        }
                    }
                }
            }
        });
    }
}
