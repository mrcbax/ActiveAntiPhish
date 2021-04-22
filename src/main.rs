use clap::{App, Arg, crate_authors, crate_description, crate_version};

pub mod types;
pub mod thread_manager;

use types::PostFields;

fn main() {
    let matches = App::new("ActiveAntiPhish")
        .about(crate_description!())
        .author(crate_authors!())
        .version(format!("{}\t{}", crate_version!(), "GNU-GPL-3.0").as_str())
        .arg(
            Arg::with_name("url")
                .help("The path to the endpoint to POST fake data to")
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
                .short("-h")
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
                .takes_value(true)
                .multiple(false)
                .required(false)
        )
        .get_matches();
    let mut fields: PostFields = PostFields::default();
    fields.email = matches.value_of("email_field");
    fields.password = matches.value_of("password_field");
    fields.phone = matches.value_of("phone_field");
    fields.fname = matches.value_of("fname_field");
    fields.lname = matches.value_of("lname_field");
    fields.ccn = matches.value_of("ccn_field");
    fields.exp = matches.value_of("exp_field");
    fields.cvv = matches.value_of("cvv_field");
}
