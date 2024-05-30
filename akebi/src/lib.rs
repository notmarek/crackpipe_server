#[macro_use]
extern crate rocket;

use std::borrow::ToOwned;
use std::fs;
use std::num::ParseIntError;

use base64::prelude::*;
use hmac::{Hmac, Mac};
use rocket::{Build, Rocket, serde, State};
use rocket::form::Form;
use rocket::FromForm;
use rocket::http::Header;
use rocket::serde::json::{Json, serde_json};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};
use sha2::Sha256;
use soft_aes::aes::{aes_dec_cbc, aes_enc_cbc};

type HmacSha256 = Hmac<Sha256>;


pub fn decrypt(data: String, key: String) -> String {
    let data = BASE64_STANDARD.decode(data).unwrap();
    let iv = b"0000000000000000"; // fuck figureing out how to get [u8; 16] during runtime.... just let CBC figure it out since the first 16 bytes are the iv anyway. we throw them away after decryption
    let data = aes_dec_cbc(&data, &decode_hex(&key).unwrap()[..], iv, Some("PKCS7")).unwrap();
    String::from_utf8(data[16..].to_owned()).unwrap()
}

pub fn encrypt(data: String, key: String) -> String {
    let iv = b"Marek says hi o/".to_owned();
    let mut data = aes_enc_cbc(&data.into_bytes(), &decode_hex(&key).unwrap()[..], &iv, Some("PKCS7")).unwrap();
    let mut out_data: Vec<u8> = Vec::from(iv);
    out_data.append(&mut data);
    BASE64_STANDARD.encode(out_data)
}

pub fn xorcrypt(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for (i, byte) in data.iter().enumerate() {
        out.push(byte ^ key[i % key.len()])
    }
    out
}

#[derive(FromForm)]
pub struct UserInput {
    // ownerid: String,
    // name: String,
    payload: String,
}

#[derive(Serialize)]
pub struct AkebiPayload {
    payload: String,
}

#[derive(Deserialize, Debug)]
struct AkebiCommonRequest {
    #[serde(rename = "type")]
    kind: String,
    sessionid: Option<String>,
    #[serde(rename = "syncKey")]
    sync_key: u32,
}

#[derive(Deserialize, Debug)]
struct AkebiHandshakeRequest {
    enckey: String,
}

// #[derive(Deserialize, Debug)]
// struct AkebiLicenseRequest {
//     // key: String,
//     // hwid: String,
// }

#[derive(Deserialize, Debug)]
struct AkebiGetVarRequest {
    cid: String,
    // varid: String,
}

#[derive(Serialize, Debug)]
struct AkebiCommonResponse {
    message: String,
    success: bool,
    #[serde(rename = "syncKey")]
    sync_key: u32,
}

#[derive(Serialize, Debug)]
struct AkebiHandshakeResponse {
    #[serde(flatten)]
    common: AkebiCommonResponse,
    sessionid: String,
}

#[derive(Serialize, Debug)]
struct AkebiLicenseResponse {
    #[serde(flatten)]
    common: AkebiCommonResponse,
    time_left: i32,
    sub_level: u32,
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

#[derive(Responder)]
#[response(status = 200, content_type = "json")]
struct AkebiResponder<T> {
    inner: Json<T>,
    signature: Header<'static>,
}


#[post("/get_ip_list", data = "<user_input>")]
fn akebi(config: &State<AkebiConfig>, user_input: Form<UserInput>) -> AkebiResponder<AkebiPayload> {
    let payload = crate::decrypt(user_input.payload.clone(), config.aes_key.clone());
    let common_data: AkebiCommonRequest = from_str(&payload).unwrap();
    let common_response = AkebiCommonResponse {
        message: "".to_owned(),
        success: true,
        sync_key: common_data.sync_key,
    };
    let mut mac = match common_data.sessionid {
        Some(sid) => HmacSha256::new_from_slice(format!("{}-{}", sid, config.hmac_key).as_bytes()).unwrap(),
        None => HmacSha256::new_from_slice(config.hmac_key.as_bytes()).unwrap()
    };

    let mut res: String = to_string(&common_response).unwrap();
    match common_data.kind.as_str() {
        "handshake" => {
            let data: AkebiHandshakeRequest = from_str(&payload).unwrap();
            res = to_string(&AkebiHandshakeResponse {
                common: common_response,
                sessionid: data.enckey,
            })
                .unwrap();
        }
        "license_login" => {
            // let data: AkebiLicenseRequest = from_str(&payload).unwrap();
            res = to_string(&AkebiLicenseResponse {
                common: common_response,
                time_left: 133769420,
                sub_level: 42,
            })
                .unwrap();
        }
        "get_variable" => {
            let data: AkebiGetVarRequest = from_str(&payload).unwrap();

            let mut cid_vec = decode_hex(&data.cid).unwrap();
            cid_vec.reverse();
            let xorkey = crate::xorcrypt(cid_vec, decode_hex(&config.cid_xorkey).unwrap().into());
            let msg = BASE64_STANDARD.encode(crate::xorcrypt(config.game_data.clone().into(), xorkey));
            res = to_string(&AkebiCommonResponse {
                message: msg,
                success: true,
                sync_key: common_data.sync_key,
            }
            )
                .unwrap();
        }
        _ => (),
    }
    let response_payload = crate::encrypt(res, config.aes_key.clone());
    mac.update(format!("{{\"payload\":\"{}\"}}", response_payload).as_bytes());
    let signature = format!("{:x}", mac.finalize().into_bytes().to_owned());
    AkebiResponder {
        inner: Json(AkebiPayload {
            payload: response_payload,
        }),
        signature: Header::new("signature", signature),
    }
}

#[derive(Deserialize, Debug)]
#[serde(crate = "rocket::serde")]
struct AkebiConfig {
    enabled: Option<bool>,
    game_data: String,
    hmac_key: String,
    aes_key: String,
    cid_xorkey: String,
}

#[derive(Deserialize, Debug)]
struct Config {
    akebi: AkebiConfig,
}

pub fn setup(rocket: Rocket<Build>) -> Rocket<Build> {
    let raw_conf = match fs::read_to_string("config.toml") {
        Ok(c) => c,
        Err(_) => return rocket
    };
    let conf: Config = match toml::from_str(&raw_conf) {
        Ok(c) => c,
        Err(_) => return rocket
    };
    if conf.akebi.enabled.is_none() || !conf.akebi.enabled.unwrap() {
        rocket
    } else {
        rocket.mount("/", routes![akebi]).manage(conf.akebi)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::{decrypt, encrypt, xorcrypt};

    #[test]
    fn decrypt_test() {
        assert_eq!(decrypt("TWFyZWsgc2F5cyBoaSBvL4ZOKniqOfbwUHzSt1dmtn6271yA/xqrSI+C+0+z8Zcd2hIFEpjsPGymBy7ehPqM0A==".to_owned()), "hello world what the sha is this lmao");
    }

    #[test]
    fn encrypt_test() {
        assert_eq!(encrypt("hello world what the sha is this lmao".to_owned()), "TWFyZWsgc2F5cyBoaSBvL4ZOKniqOfbwUHzSt1dmtn6271yA/xqrSI+C+0+z8Zcd2hIFEpjsPGymBy7ehPqM0A==");
    }

    #[test]
    fn xorcrypt_test() {
        let mut cid = Vec::from(hex!("31 32 38 c2 56 4e 4d 83"));
        cid.reverse();
        assert_eq!(xorcrypt(cid, vec![0x1f, 0xf0, 0x40, 0x0e, 0, 0, 0, 0]), hex!("9c bd 0e 58 c2 38 32 31"))
    }
}
