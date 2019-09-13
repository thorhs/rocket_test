#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

extern crate rocket_contrib;

#[macro_use]
extern crate serde_derive;

use rocket::http::RawStr;
use rocket::request::Form;
use rocket::request::FromFormValue;
use rocket_contrib::json::Json;

use jwt::claims::Registered;
use jwt::header::Header;
use jwt::Token;

struct GlobalAddr(String);

impl<'v> FromFormValue<'v> for GlobalAddr {
    type Error = &'v RawStr;

    fn from_form_value(form_value: &'v RawStr) -> Result<GlobalAddr, &'v RawStr> {
        match form_value.parse::<String>() {
            Ok(addr) if addr.starts_with('G') && addr.len() == 56 => Ok(GlobalAddr(addr)),
            _ => Err(form_value),
        }
    }
}

struct SecretAddr(String);

impl<'v> FromFormValue<'v> for SecretAddr {
    type Error = &'v RawStr;

    fn from_form_value(form_value: &'v RawStr) -> Result<SecretAddr, &'v RawStr> {
        match form_value.parse::<String>() {
            Ok(addr) if addr.starts_with('S') && addr.len() == 56 => Ok(SecretAddr(addr)),
            _ => Err(form_value),
        }
    }
}

#[derive(Serialize)]
struct AuthResponse {
    transaction: String,
    network_passphrase: String,
}

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[get("/auth?<account>")]
fn auth(account: GlobalAddr) -> Json<AuthResponse> {
    Json(AuthResponse {
        transaction: "transaction".into(),
        network_passphrase: "Public Global Stellar Network ; September 2015".into(),
    })
}

#[derive(Deserialize, FromForm)]
struct AuthTransaction {
    transaction: String,
}

#[derive(Serialize)]
struct AuthToken {
    token: String,
}

struct AuthTokenData {
    iss: String,
    sub: String,
    iat: u32,
    exp: u32,
    jti: String,
}

fn authenticate_token(auth_tx: &AuthTransaction) -> Result<String, String> {
  let registered = Registered{
    iss: Some("iss".into()),
    sub: Some("sub".into()),
    iat: Some(123),
    exp: Some(234),
    jti: Some("jti".into()),
    ..Default::default()
  };

  let headers = Header::default();

  let token = Token::new(headers, registered);

  token.signed("fdjskfjsklfsjklfdsjklfdsjkfdsjfdkljfdsk", 
}

#[post("/token", format = "application/json", data = "<auth_tx>", rank = 1)]
fn token_json(auth_tx: Json<AuthTransaction>) -> Json<AuthToken> {
    Json(AuthToken {
        token: authenticate_token(auth_tx),
    })
}

#[post(
    "/token",
    format = "application/x-www-form-urlencoded",
    data = "<auth_tx>",
    rank = 2
)]
fn token_form(auth_tx: Form<AuthTransaction>) -> Json<AuthToken> {
    Json(AuthToken {
        token: authenticate_token(auth_tx),
    })
}

fn main() {
    rocket::ignite()
        .mount("/", routes![index, auth, token_json, token_form])
        .launch();
}
