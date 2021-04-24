# ActiveAntiPhish

---
This readme is a bit outdated. You can read the blog post about ActiveAntiPhish for more info [https://computeco.de/posts/2019-06-16_1.html](https://computeco.de/posts/2019-06-16_1.html)

## Latest Update 2021-03-24_01:27:00_EST

Theory
---

This repo takes advantage of a technique called database saturation. If your organization is successfully phished this tool allows the organization to increase the noise in the signal to noise ratio of the hacker's stolen credentials. This is done by providing the tool with a fake password list, fake username list, proxy list, the phishing page's callback url, and your organizations email domain extension.

It generates hundreds of fake username/password pairs that are injected into the phishing page.

The theory is that the phisher will abandon their database as validating thousands of fake accounts just to find the small amount of valid accounts is very annoying.

Practice
---

You can use the ActiveAntiPhish command line application by compiling it with the [rust toolchain](https://rustup.rs). Then, run `cargo install aap`. You will then be able to run the `aap` program from the command line.

## `aap` Help

```
ActiveAntiPhish 0.2.1	GNU-GPL-3.0
Chad Baxter <cbax@doslabelectronics.com>
Saturate the bad guys' databases.

USAGE:
    aap [FLAGS] [OPTIONS] --time <run_time> --threads <threads> --url <url>

FLAGS:
    -g, --debug         Locks application to one thread and displays HTTP response data.
    -h, --help          Prints help information
    -m, --multipart     The form uses multipart data.
    -w, --urlencoded    The form uses www-urlencoded data.
    -V, --version       Prints version information

OPTIONS:
    -c, --ccn <ccn_field>             The form field where a credit card number should be populated.
    -v, --cvv <cvv_field>             The form field where a credit card verification value should be populated.
    -d, --domain <domain>             The domain of the email server associated with your organization (otherwise random
                                      domains will be used). For example: example.com or mail.example.com
    -e, --email <email_field>         The form field where an email should be populated.
    -x, --exp <exp_field>             The form field where a credit card expiration date should be populated.
    -f, --fname <first_name_field>    The form field where a first name should be populated.
    -l, --lname <last_name_field>     The form field where a last name should be populated.
    -p, --pass <password_field>       The form field where an password should be populated.
    -o, --phone <phone_field>         The form field where an phone number should be populated.
    -t, --time <run_time>             Number of seconds until program exits.
    -n, --threads <threads>           Number of threads to use. Default: 20
    -u, --url <url>                   The path to the endpoint to POST fake data to.
```

Phish Kit Collection
---
This project maintains a collection of active and inactive phish kits that are unredacted. They are encrypted to protect from leechers and to protect the identities of hackers. Please contact me to be vetted for the decryption password.

YARA Rules
---
In the `rules` directory you can find a yara ruleset for the phishkits in this repo as well as a generic rule for detecting phishing page source code (phish kits all use a similar design/coding style).

Advisories
---
You can find current phishing advisories in `ADVISORIES.md`.
