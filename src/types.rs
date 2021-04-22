#[derive(Default)]
pub struct PostFields<'a> {
    pub email: Option<&'a str>,
    pub password: Option<&'a str>,
    pub phone: Option<&'a str>,
    pub fname: Option<&'a str>,
    pub lname: Option<&'a str>,
    pub ccn: Option<&'a str>,
    pub exp: Option<&'a str>,
    pub cvv: Option<&'a str>
}

#[derive(Default)]
pub struct PostData {
    pub email: Option<String>,
    pub password: Option<String>,
    pub phone: Option<String>,
    pub fname: Option<String>,
    pub lname: Option<String>,
    pub ccn: Option<String>,
    pub exp: Option<String>,
    pub cvv: Option<String>
}
