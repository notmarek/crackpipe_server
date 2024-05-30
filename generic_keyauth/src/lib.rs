#[macro_use]
extern crate rocket;

use std::borrow::ToOwned;
use std::fs;

use hmac::{Hmac, Mac};
use rocket::{Build, Rocket, serde, State};
use rocket::form::Form;
use rocket::FromForm;
use rocket::http::Header;
use rocket::response::Responder;
use rocket::serde::json::{Json, serde_json};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(FromForm, Debug)]
pub struct Request {
    enckey: Option<String>,
    sessionid: Option<String>,
    name: String,
    ownerid: String,
    #[field(name = "type")]
    kind: String,
}

#[derive(Serialize)]
struct BasicResponse {
    success: bool,
    message: String,
    nonce: String,
}

#[derive(Serialize, Default)]
struct AppInfoResponse {
    #[serde(rename = "numUsers")]
    num_users: String,
    #[serde(rename = "numOnlineUsers")]
    num_online_users: String,
    #[serde(rename = "numKeys")]
    num_keys: String,
    version: String,
    #[serde(rename = "customerPanelLink")]
    customer_panel_link: String,
}

#[derive(Serialize)]
struct InitResponse {
    #[serde(flatten)]
    basic: BasicResponse,
    sessionid: String,
    appinfo: AppInfoResponse,
    #[serde(rename = "newSession")]
    new_session: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SubInfo {
    subscription: String,
    key: String,
    expiry: String,
    timeleft: u32,
    level: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct LicenseInfo {
    username: String,
    subscriptions: Vec<SubInfo>,
    ip: String,
    hwid: String,
    #[serde(rename = "createdate")]
    creation_date: String,
    lastlogin: String,
}

impl Default for LicenseInfo {
    fn default() -> LicenseInfo {
        LicenseInfo {
            username: "Unk".to_string(),
            subscriptions: vec![SubInfo {
                subscription: "default".to_string(),
                key: String::new(),
                expiry: String::new(),
                timeleft: 0,
                level: 1,
            }],
            ip: "127.0.0.1".to_string(),
            hwid: String::new(),
            creation_date: String::new(),
            lastlogin: String::new(),
        }
    }
}

#[derive(Serialize)]
struct LicenseResponse {
    #[serde(flatten)]
    basic: BasicResponse,
    info: LicenseInfo,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ResponseEnum {
    License(LicenseResponse),
    Init(InitResponse),
    Basic(BasicResponse),
}

impl ResponseEnum {
    pub fn sign(&self, instance: &Instance, enckey: Option<String>) -> String {
        let data: String = serde_json::to_string(&self).unwrap();
        let key: String = match enckey {
            Some(enc) => format!("{}-{}", enc, &instance.secret),
            None => instance.secret.clone()
        };
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
        mac.update(data.as_bytes());
        let signature = format!("{:x}", mac.finalize().into_bytes().to_owned());
        signature
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
struct Instance {
    friendly_name: Option<String>,
    license_info: Option<LicenseInfo>,
    owner: String,
    app: String,
    secret: String,
}

impl Instance {
    fn get_display_name(&self) -> String {
        match self.friendly_name.clone() {
            Some(friendly) => friendly,
            None => self.app.clone()
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct KeyAuth {
    instances: Vec<Instance>,
}

#[derive(Responder)]
#[response(status = 200, content_type = "json")]
pub struct KeyAuthResponder<T> {
    inner: Json<T>,
    signature: Header<'static>,
    handler: Header<'static>,
}

#[post("/api/1.2", data = "<request>")]
fn keyauth(app_config: &State<KeyAuth>, request: Form<Request>) -> Option<KeyAuthResponder<impl Serialize>> {
    let instance = app_config.instances.iter().find(|inst| inst.app == request.name && inst.owner == request.ownerid)?;
    println!("Keyauth request: {:#?}", request);
    let res = match request.kind.as_str() {
        "init" => {
            ResponseEnum::Init(InitResponse {
                basic: BasicResponse {
                    success: true,
                    message: String::new(),
                    nonce: String::from("A very random nonce ;)"),
                },
                sessionid: request.enckey.clone().unwrap(),
                appinfo: AppInfoResponse::default(),
                new_session: true,
            })
        }
        "checkblacklist" => {
            ResponseEnum::Basic(BasicResponse {
                success: false,
                // === not found in the blacklist
                message: String::new(),
                nonce: String::from("A very random nonce ;)"),
            })
        }
        "license" => {
            ResponseEnum::License(LicenseResponse {
                basic: BasicResponse {
                    success: true,
                    message: String::new(),
                    nonce: String::from("A very random nonce ;)"),
                },
                info: instance.license_info.clone().unwrap_or_default(),
            })
        }
        _ => {
            ResponseEnum::Basic(BasicResponse {
                success: true,
                message: String::new(),
                nonce: String::from("A very random nonce ;)"),
            })
        }
    };
    let signature = Header::new("signature", res.sign(instance, request.sessionid.clone()));
    Some(KeyAuthResponder {
        inner: Json(res),
        handler: Header::new("handler", instance.get_display_name()),
        signature,
    })
}

#[derive(Deserialize, Debug)]
struct KeyAuthConfig {
    enabled: Option<bool>,
    instances: Option<Vec<Instance>>,
}

#[derive(Deserialize, Debug)]
struct Config {
    keyauth: KeyAuthConfig,
}

pub fn setup(rocket: Rocket<Build>) -> Rocket<Build> {
    let raw_conf = match fs::read_to_string("config.toml") {
        Ok(c) => c,
        Err(_) => return rocket
    };
    let conf: Config = match toml::from_str(&raw_conf) {
        Ok(c) => c,
        Err(e) => { println!("{:#?}", e); return rocket }
    };

    if conf.keyauth.enabled.is_none() || !conf.keyauth.enabled.unwrap() {
        rocket
    } else {
        let mut apps = conf.keyauth.instances.clone().unwrap().into_iter().map(|i| i.friendly_name.unwrap_or(i.app)).collect::<Vec<String>>().join(", ");
        let last = apps.rfind(", ").unwrap();
        apps.replace_range(last..last+2, " and ");
        println!("Setup keyauth for {}.", apps);
        rocket.mount("/", routes![keyauth]).manage(KeyAuth {
            instances: conf.keyauth.instances.unwrap()
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
