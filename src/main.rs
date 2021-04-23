use clap::{App, Arg, crate_authors, crate_description, crate_version};

pub mod types;
pub mod thread_manager;
pub mod request_builder;
pub mod generator;

use types::PostFields;
use thread_manager::*;

fn main() {
    let matches = App::new("ActiveAntiPhish")
        .about(crate_description!())
        .author(crate_authors!())
        .version(format!("{}\t{}", crate_version!(), "GNU-GPL-3.0").as_str())
        .arg(
            Arg::with_name("url")
                .help("The path to the endpoint to POST fake data to.")
                .short("-u")
                .long("--url")
                .takes_value(true)
                .multiple(false)
                .required(true)
        )
        .arg(
            Arg::with_name("domain")
                .help("The domain of the email server associated with your organization (otherwise random domains will be used). For example: example.com or mail.example.com")
                .short("-d")
                .long("--domain")
                .takes_value(true)
                .multiple(false)
                .required(false)
        )
        .arg(
            Arg::with_name("run_time")
                .help("Number of seconds until program exits.")
                .short("-t")
                .long("--time")
                .takes_value(true)
                .multiple(false)
                .required(true)
        )
        .arg(
            Arg::with_name("threads")
                .help("Number of threads to use. Default: 20")
                .short("-n")
                .long("--threads")
                .takes_value(true)
                .multiple(false)
                .required(true)
        )
        .arg(
            Arg::with_name("email_field")
                .help("The form field where an email should be populated.")
                .short("-e")
                .long("--email")
                .takes_value(true)
                .multiple(false)
                .required(false)
        )
        .arg(
            Arg::with_name("password_field")
                .help("The form field where an password should be populated.")
                .short("-p")
                .long("--pass")
                .takes_value(true)
                .multiple(false)
                .required(false)
        )
        .arg(
            Arg::with_name("phone_field")
                .help("The form field where an phone number should be populated.")
                .short("-o")
                .long("--phone")
                .takes_value(true)
                .multiple(false)
                .required(false)
        )
        .arg(
            Arg::with_name("first_name_field")
                .help("The form field where a first name should be populated.")
                .short("-f")
                .long("--fname")
                .takes_value(true)
                .multiple(false)
                .required(false)
        )
        .arg(
            Arg::with_name("last_name_field")
                .help("The form field where a last name should be populated.")
                .short("-l")
                .long("--lname")
                .takes_value(true)
                .multiple(false)
                .required(false)
        )
        .arg(
            Arg::with_name("ccn_field")
                .help("The form field where a credit card number should be populated.")
                .short("-c")
                .long("--ccn")
                .takes_value(true)
                .multiple(false)
                .required(false)
                .requires("exp_field")
                .requires("cvv_field")
        )
        .arg(
            Arg::with_name("exp_field")
                .help("The form field where a credit card expiration date should be populated.")
                .short("-x")
                .long("--exp")
                .takes_value(true)
                .multiple(false)
                .required(false)
        )
        .arg(
            Arg::with_name("cvv_field")
                .help("The form field where a credit card verification value should be populated.")
                .short("-v")
                .long("--cvv")
                .takes_value(true)
                .multiple(false)
                .required(false)
        )
        .arg(
            Arg::with_name("debug")
                .help("Locks application to one thread and displays HTTP response data.")
                .short("-g")
                .long("--debug")
                .takes_value(false)
                .multiple(false)
                .required(false)
        )
        .get_matches();
    let mut fields: PostFields = PostFields::default();
    fields.email = match matches.value_of("email_field") {
        Some(s) => Some(s.to_string()),
        None => None
    };
    fields.password = match matches.value_of("password_field") {
        Some(s) => Some(s.to_string()),
        None => None
    };
    fields.phone = match matches.value_of("phone_field") {
        Some(s) => Some(s.to_string()),
        None => None
    };
    fields.fname = match matches.value_of("fname_field") {
        Some(s) => Some(s.to_string()),
        None => None
    };
    fields.lname = match matches.value_of("lname_field") {
        Some(s) => Some(s.to_string()),
        None => None
    };
    fields.ccn = match matches.value_of("ccn_field") {
        Some(s) => Some(s.to_string()),
        None => None
    };
    fields.exp = match matches.value_of("exp_field") {
        Some(s) => Some(s.to_string()),
        None => None
    };
    fields.cvv = match matches.value_of("cvv_field") {
        Some(s) => Some(s.to_string()),
        None => None
    };

    let url = match matches.value_of("url") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("A URL was not provided.");
            std::process::exit(1);
        }
    };

    let domain = match matches.value_of("domain") {
        Some(s) => s.to_string(),
        None => String::new()
    };

    let threads: u64 = match matches.value_of("threads") {
        Some(s) => {
            match s.parse::<u64>() {
                Ok(o) => o,
                Err(_) => {
                    eprintln!("Number of threads is not a number!");
                    std::process::exit(1);
                }
            }
        },
        None => 20
    };

    let sleep: u64 = match matches.value_of("run_time") {
        Some(s) => {
            match s.parse::<u64>() {
                Ok(o) => o,
                Err(_) => {
                    eprintln!("Run time is not a number!");
                    std::process::exit(1);
                }
            }
        },
        None => {
            eprintln!("Run time not specified, is required.");
            std::process::exit(1);
        }
    };

    if !matches.is_present("debug") {
        execute(fields, url, domain, 1, true);
    } else {
        execute(fields, url, domain, threads, false);
    }
    std::thread::sleep(std::time::Duration::from_secs(sleep));
}
