#[macro_use] extern crate rocket;
use rocket::http::{CookieJar, Header, Status};
use rocket::State;
use rocket::response::Redirect;
use hmac::{Hmac, Mac};
use jwt::{SignWithKey,VerifyWithKey};
use sha2::Sha256;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use urlencoding;
use base64::prelude::*;
use hex;

struct JWTKey {
    hmac: Hmac<Sha256>
}

struct DiscourseKey {
    hmac: Hmac<Sha256>
}

#[derive(Responder)]
enum AuthResponse {
    Authorized {
        inner: Status,
        user_id: Header<'static>
    },
    Unauthorized {
        inner: Status,
        redirect_url: Header<'static>
    }
}

#[get("/auth")]
fn auth(cookies: &CookieJar<'_>, key: &State<JWTKey>) -> AuthResponse {
    if let Some(token) = cookies.get("jwtauth") {
        let claims: Result<BTreeMap<String, String>, jwt::Error> = token.value().verify_with_key(&key.hmac);
        if let Ok(_claims) = claims {
            return AuthResponse::Authorized {
                inner: Status::Ok,
                user_id: Header::new("X-Authentication-Id", value)
            };
        }
    }


    Status::Unauthorized
}

#[get("/login")]
fn login(cookies: &CookieJar<'_>, key: &State<JWTKey>, discourse_key: &State<DiscourseKey>) -> Redirect {
    let return_url = "";

    let nonce = "not-a-nonce";
    let mut auth_return = Url::parse("http://127.0.0.1:8000/validate").unwrap();
    auth_return.query_pairs_mut().append_pair("return_url", return_url);

    let raw_payload = format!("nonce={}&return_sso_url={}", urlencoding::encode(nonce), urlencoding::encode(auth_return.as_str()));
    let base64_payload = BASE64_STANDARD.encode(raw_payload);
    let mut discourse_hmac = discourse_key.hmac.clone();
    discourse_hmac.update(base64_payload.as_bytes());
    let sig = hex::encode(discourse_hmac.finalize().into_bytes());

    let mut redirect = Url::parse("https://bristolhackspace.discourse.group/session/sso_provider").unwrap();
    redirect.query_pairs_mut().append_pair("sso", &base64_payload);
    redirect.query_pairs_mut().append_pair("sig", &sig);
    let redirect: String = redirect.into();

    Redirect::to(redirect)
}

#[get("/validate?<return_url>&<sso>&<sig>")]
fn validate(return_url: &str, sso: &str, sig: &str, cookies: &CookieJar<'_>, key: &State<JWTKey>, discourse_key: &State<DiscourseKey>) -> Result<Redirect, Status> {
    let mut discourse_hmac = discourse_key.hmac.clone();
    discourse_hmac.update(sso.as_bytes());
    let calculated_sig = hex::encode(discourse_hmac.finalize().into_bytes());
    if sig != calculated_sig {
        return Err(Status::BadRequest);
    }

    let raw_payload = BASE64_STANDARD.decode(sso.as_bytes()).map_err(|e| Status::BadRequest)?;
    let raw_payload = String::from_utf8(raw_payload).map_err(|e| Status::BadRequest)?;

    let mut query_params = BTreeMap::new();

    for pair in raw_payload.split("&") {
        let mut it = pair.split('=').take(2);
        if let (Some(k), Some(v)) = (it.next(), it.next()) {
            let v = urlencoding::decode(v).map_err(|e| Status::BadRequest)?;
            query_params.insert(Cow::Borrowed(k), v);
        }
    }

    println!("{:?}", query_params);

    let user_id = query_params.get("external_id").ok_or(Status::BadRequest)?;

    let mut claims = BTreeMap::new();
    claims.insert("sub", user_id.to_owned());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expiry = now + (3600*24);
    claims.insert("exp", Cow::from(expiry.to_string()));

    if let Ok(token_str) = claims.sign_with_key(&key.hmac) {
        cookies.add(("jwtauth", token_str));
    }

    Ok(Redirect::to(return_url.to_owned()))
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![auth, login, validate])
        .manage(JWTKey{hmac: Hmac::new_from_slice(b"\x90\x0f\x8f\xbdP\x08&\x7f\x15\xd6\x1d\"n,<\xde.Jp\xaa_\xe8\xa68\xbf\x9d\xfe\x97W\x02o\xfe").unwrap()})
        .manage(DiscourseKey{hmac: Hmac::new_from_slice(b"550df86818a280c1d4b1d34be4816ca7188580b4cff9beff9f5e17a4422a53e0").unwrap()})
}
