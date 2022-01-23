#[derive(Default, Clone)]
pub struct PostFields {
    pub email: Option<String>,
    pub password: Option<String>,
    pub phone: Option<String>,
    pub fname: Option<String>,
    pub lname: Option<String>,
    pub ccn: Option<String>,
    pub exp: Option<String>,
    pub cvv: Option<String>,
    pub custom: Vec<String>,
    pub cookies: Vec<String>
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
    pub cvv: Option<String>,
    pub custom: Vec<String>,
    pub cookies: Vec<String>
}
