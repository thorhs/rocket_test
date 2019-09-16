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

extern crate jsonwebtoken as jwt;

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
    token: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthTokenData {
    iss: String,
    sub: String,
    iat: u32,
    exp: u32,
    jti: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GenericError {
    error: String,
}

fn authenticate_token(auth_tx: &AuthTransaction) -> Result<String, String> {
    let claims = AuthTokenData {
        iss: "https://127.0.0.1".to_owned(),
        sub: "sub".to_owned(),
        iat: 123,
        exp: 234,
        jti: auth_tx.transaction.to_owned(),
    };

    match jwt::encode(&jwt::Header::default(), &claims, "secret".as_ref()) {
        Ok(token) => Ok(token),
        Err(err) => Err(err.to_string()),
    }
}

#[post("/token", format = "application/json", data = "<auth_tx>", rank = 1)]
fn token_json(auth_tx: Json<AuthTransaction>) -> Json<AuthToken> {
    match authenticate_token(&auth_tx) {
        Ok(token) => Json(AuthToken {
            token: Some(token),
            error: None,
        }),
        Err(error) => Json(AuthToken {
            token: None,
            error: Some(error),
        }),
    }
}

#[post(
    "/token",
    format = "application/x-www-form-urlencoded",
    data = "<auth_tx>",
    rank = 2
)]
fn token_form(auth_tx: Form<AuthTransaction>) -> Json<AuthToken> {
    match authenticate_token(&auth_tx) {
        Ok(token) => Json(AuthToken {
            token: Some(token),
            error: None,
        }),
        Err(error) => Json(AuthToken {
            token: None,
            error: Some(error),
        }),
    }
}

fn main() {
    rocket::ignite()
        .mount("/", routes![index, auth, token_json, token_form])
        .launch();
}
