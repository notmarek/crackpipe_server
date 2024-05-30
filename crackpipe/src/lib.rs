#[macro_use]
extern crate rocket;

use std::fs;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ring::{rand, rsa, signature};
use rocket::{Build, Rocket, routes, State};
use rocket::serde::Deserialize;
use rocket::serde::json::Json;
use serde::Serialize;

#[derive(Deserialize, Serialize, Clone)]
struct CrackPipeUser {
    hwid: String,
    id: String,
    nonce: String,
    username: String,
}

#[derive(Deserialize)]
struct CrackPipeConfig {
    enabled: Option<bool>,
    rsa_key: String,
    users: Vec<CrackPipeUser>,
}

#[derive(Deserialize)]
struct Config {
    crackpipe: CrackPipeConfig,
}

static RSA_HEADER: &str = "-----BEGIN RSA PRIVATE KEY-----\n";
static RSA_FOOTER: &str = "-----END RSA PRIVATE KEY-----\n";

fn pem_to_der(key: &str) -> Option<Vec<u8>> {
    let header = key.find(RSA_HEADER)?;
    let footer = key.find(RSA_FOOTER)?;
    let inner = &key[header + RSA_HEADER.len()..footer];
    let data = inner.replace("\n", "");
    let der = BASE64_STANDARD.decode(data.as_bytes()).ok()?;
    Some(der)
}

fn generate_signature(key: &str, data: String) -> Option<String> {
    let key_pair = rsa::KeyPair::from_der(&pem_to_der(key)?).unwrap();
    let rng = rand::SystemRandom::new();
    let mut signature = vec![0; key_pair.public().modulus_len()];
    key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, data.as_bytes(), &mut signature).ok()?;
    Some(BASE64_STANDARD.encode(&signature))
}

#[derive(Serialize)]
struct SignedUser {
    data: CrackPipeUser,
    sig: String,
}

#[derive(Serialize)]
struct HwidResponse {
    msg: String,
    sig: String,
}

#[get("/crackpipe/<uid>/key.json")]
fn generate_keyfile(config: &State<CrackPipeConfig>, uid: &str) -> Option<Json<SignedUser>> {
    let user = config.users.iter().find(|user| user.id == uid)?;
    let user_json = serde_json::to_string(user).ok()?;
    let sig = generate_signature(&config.rsa_key, user_json)?;
    Some(Json(
        SignedUser {
            data: user.clone(),
            sig,
        }
    ))
}

#[get("/dll/<hwidsus>")]
fn verify_hwid(config: &State<CrackPipeConfig>, hwidsus: &str) -> Option<Json<HwidResponse>> {
    if hwidsus.len() < 4 {
        return None;
    }
    let hwid = &hwidsus[..hwidsus.len() - 4];
    let user = config.users.iter().find(|user| user.hwid == hwid)?;
    let mut rng = rand::SystemRandom::new();
    let nonce = rand::generate::<[u8; 16]>(&mut rng).unwrap().expose();

    let msg = format!("{};{}", &user.username, String::from_utf8_lossy(&nonce));
    let sig = generate_signature(&config.rsa_key, msg.clone())?;
    Some(Json(HwidResponse {
        msg,
        sig,
    }))
}

#[get("/sus/<uidsig>")]
fn verify_sig(config: &State<CrackPipeConfig>, uidsig: &str) -> Option<String> {
    if uidsig.len() < 4 {
        return None;
    }
    let uid = &uidsig[..uidsig.len() - 4];
    let user = config.users.iter().find(|user| user.id == uid)?;
    let user_json = serde_json::to_string(user).ok()?;
    let sig = generate_signature(&config.rsa_key, user_json)?;
    Some(sig)
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
    if conf.crackpipe.enabled.is_none() || !conf.crackpipe.enabled.unwrap() {
        rocket
    } else {
        rocket.mount("/", routes![verify_sig, verify_hwid, generate_keyfile]).manage(conf.crackpipe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_test() {
        let key = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3O8cqJTfJ5OGLPDgg0q5uFp+AAtt5UJrMNrHYqRp7nRbqfvz
OhFKj/BjILIcxm5uEsdySyDX0WmPslx/GKkWZU1MUTuOpc6LhnUiwjkDvrCDsvZ8
EjwG2Ez3DkQA+2070dTzOIi9E5nbEawCvy2KsCIeZ/jhUmRQbC2vfWqZsBGB108f
AnvsXfNF/rViYeJiPBoi4c76y/jjFEYqzncBdASzI3HrHAvMdAfGnjpTIW+gGDKJ
blTxCbObx/GjSFqE+Kfg2G8Sg7+YjpWLch3jO/6wpZ7gdiUyoiv4H9pHSHBSn0Yb
+GKkAvw1Rje6T/H91e5oE6kgBx0k6x8xJ7QfqwIDAQABAoIBAERMlyt2elYdwQj7
nix4WVmof/M7lUmecsyzlZflA+p3hi7SeKqm1coRolNlPIgLc3PSvH6FNLLEU2vs
NE5HV2kRsFocc0jGxVNXutsYDRRSNSSKFmj8rZEImgeK9lLDvg5sKpR7kRgSJCse
Zer8BTfWFFhIFEAISuRmay32WnSXIdExrTMWnutPDXmNvfvUc04tTZvYaN2XZI//
EM/8xQ65PfqRJOHZvFRLpCGl8D6IagUYSQ9HN7sYZZUX5PLZoMKQt3Pw0+e2FEgn
1L6Inla1blVwn5I1Kj7PdR4fQb+zg5hpsbsjUQCB0wGG9UM1Iq7w4c5+gUFoThx/
bnjU+MECgYEA9dXzsUCwrXx24KExlJ1pUFehbhKhXuEGSaYnOsohOMimwSgVWgOK
bHGujAYSBnqndVYG5fH4nuFEq0SLE4q86sPgJh7rxIhIoIIlQEgw7py5a3mph7m3
BHVR+RSv5bB58koJRvIsocByaYWDr0XBN9kcbYEIJAvgBZH9tjpSLiMCgYEA5hGW
e7J7T9a+83wAjLLnXZKVkarc4gvMG+OjTJ+iMQwGzOLCHVCGQApVr3vgtOpmaPUw
kImmYP0D7nkFSoNBq3BaBpTQsBROiOBdIF/jZFSfH1ROCWX+HvZLUH+2fOZjm8W6
2/ApOD30JPgfw/L2BMLNa6UslkpEqNCYROS/LNkCgYASZTgfA2A1GyMqG+XB4SWI
RYZm3i4FE4GM8UnuNEHYJeuUeJNgcPNiuf79q1ad9X+iYBWUD08zVFf3GOHvTGpm
htG3CIlL44bLu/FdpglDUabuS+RLq7HuO3ku0kV3QoVdg/y9ulFsqSHmk38PFoEm
1LAz4XvidqEEya/aevK7UQKBgQCWrMQaRPz/f8vVGMwfWXevT7YHDZjVrhZB2ab0
IsQNTSwS+RtaKYeS33HYmM/EjJL/gD0LHCtL78ioYLf3YdkbV1yOXN4Dw3jfqdkz
v7jj14vS79qfyx1P18vhb5LrX9OyjB/htPq569E+eQYMxc0btxzjt+xojUFEMkDX
NdyCmQKBgBbCBJG25OeDamb9cUmhOEwsMc/JUIhK7R/OeYFOd4PzH1DsDhiufXSB
lSGn8BPU8+5ud94DlulBhQ8OymGaAiVDThdlIkYVe76GzjjrSnTSv40R0oaOPwhf
UINOsDfZtLAvAL0zDpg/yMKtDKi/UVkl1sAxlQkQ7r/trM6w1+F3
-----END RSA PRIVATE KEY-----
";
        let sig = generate_signature(key, "signme!".to_string());
        assert_eq!(sig.unwrap(), "PoCS5kv7GkClP35iSQgdbgYqeR750i8nnZLHkCFAtE5gsSAdZxFis8GStNH9RFsCu5Zxls9tg8i01ujUmWHqqXH7ylG/6y3vSHhbs1G7BSVOXXiVsDhqtpppIJq1gh4zhM64N3Ae1DQZYlPfGDxj5UQe3hsdVDK8zOd9cAK+4YLNN5J/E6UEnWtoukSeRnJ/DJZ32GR86YY0FD5w6UIb5K2uqR8qUreqaxrKhQjAJStegUOZEV0rUseyOAWmJaB+JcPCfu3M1t30dh/NwQXKwsQBQFcKdBaJTm1l35kO2nquyZ6f7Rhi/E5BBNLmSJRosfQVizMAh6kj6fYatnGXtQ==")
    }
}
