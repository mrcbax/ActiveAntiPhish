use crate::types::*;
use crate::request_builder::*;
use crate::generator::*;

pub fn execute(fields: PostFields, url: String, domain: String, threads: u64, debug: bool) {
    for _ in 0..threads {
        let fields_clone = fields.clone();
        let domain_clone = domain.clone();
        let url_clone = url.clone();
        let debug_clone = debug.clone();
        std::thread::spawn(move || {
            loop {
                let domain_clone1 = domain_clone.clone();
                let url_clone1 = url_clone.clone();
                let fields_clone1 = fields_clone.clone();
                let fields_clone2 = fields_clone.clone();
                let debug_clone1 = debug_clone.clone();
                let client = reqwest::blocking::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
                let response = match client.execute(
                    build_request(
                        build_form(
                            fields_clone1,
                            generate_from_fields(
                                fields_clone2,
                                domain_clone1
                            )
                        ),
                        url_clone1
                    )
                ) {
                    Ok(o) => Some(o),
                    Err(e) => {
                        if debug_clone1 {
                            println!("{:?}", e);
                        } else {
                            eprint!("✘");
                        }
                        None
                  }
                };
                if response.is_some() {
                    let res = response.unwrap();
                    if res.status().is_success() | res.status().is_redirection() {
                        if debug_clone1 {
                            println!("{:?}", res.headers());
                            println!("{:?}", res.text());
                        } else {
                            print!("✔");
                        }
                    } else {
                        print!("✘");
                    }
                }
            }
        });
    }
}
