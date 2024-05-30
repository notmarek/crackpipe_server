#[macro_use]
extern crate rocket;

use std::fs;

use base64::prelude::*;
use rocket::{Build, Rocket, State};
use rocket::serde::json::Json;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::DecodeRsaPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use sha2::{Digest, Sha256};
use soft_aes::aes::{aes_dec_cbc, aes_enc_cbc};

use useful_macros::Checksum;

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct KeyData {
    user_id: u32,
    hwid: String,
    role: u8,
    cardstr: String,
    data_id: u32,
    expiry_time: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RawKeyFile {
    #[serde(rename = "Encrypted.md5")]
    md5: String,
    #[serde(rename = "privatekey_pkcs1.pem.enc")]
    encrypted_rsa_key: String,
    #[serde(rename = "encrypted.dat")]
    encrypted_data: String,
}

impl RawKeyFile {
    pub fn get_key(&self) -> Vec<u8> {
        format!("{:x}", md5::compute(BASE64_STANDARD.decode(&self.md5).unwrap())).as_bytes().to_owned()
    }

    pub fn get_rsa_key(&self) -> Result<String, String> {
        let key = self.get_key();
        let iv = b"ABCDEF0123456789".to_owned();
        let data = aes_dec_cbc(&BASE64_STANDARD.decode(&self.encrypted_rsa_key).unwrap(), &key, &iv, Some("PKCS7")).unwrap();
        Ok(String::from_utf8(data).unwrap())
    }

    pub fn get_data(&self) -> Result<KeyData, String> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(&self.get_rsa_key().unwrap()).unwrap();
        let dec_data = private_key.decrypt(Pkcs1v15Encrypt, &BASE64_STANDARD.decode(&self.encrypted_data).unwrap()).expect("failed to decrypt");
        let dec_data_str = String::from_utf8(dec_data).unwrap();
        let data: KeyData = serde_json::from_str(&dec_data_str).unwrap();
        Ok(data)
    }
}

#[derive(Default)]
pub struct KeyFile {
    pub md5: String,
    pub rsa_key: String,
    pub data: KeyData,
}

impl KeyFile {
    pub fn from_string(data: String) -> Result<Self, serde_json::Error> {
        let raw_key: RawKeyFile = from_str(&data)?;
        Ok(Self {
            data: raw_key.get_data().unwrap(),
            md5: raw_key.md5.clone(),
            rsa_key: raw_key.get_rsa_key().unwrap(),
        })
    }
    pub fn get_key(&self) -> Vec<u8> {
        format!("{:x}", md5::compute(BASE64_STANDARD.decode(&self.md5).unwrap())).as_bytes().to_owned()
    }
    pub fn export(&self) -> RawKeyFile {
        let key = self.get_key();
        let iv = b"ABCDEF0123456789".to_owned();
        let data = aes_enc_cbc(self.rsa_key.as_bytes(), &key, &iv, Some("PKCS7")).unwrap();
        let encrypted_rsa_key = BASE64_STANDARD.encode(data);

        let private_key = RsaPrivateKey::from_pkcs1_pem(&self.rsa_key).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let mut rng = rand::thread_rng();
        let data = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, serde_json::to_string(&self.data).unwrap().as_bytes()).expect("failed to encrypt");
        let encrypted_data = BASE64_STANDARD.encode(data);

        RawKeyFile {
            md5: self.md5.clone(),
            encrypted_rsa_key,
            encrypted_data,
        }
    }
}


#[get("/changelog")]
fn get_changelog(config: &State<KorepiConfig>) -> Json<KorepiResponse<KorepiChangelogResponse>> {
    let data = &config.changelog;
    Json(KorepiResponse {
        msg: "CrackPipe!".to_string(),
        code: 200,
        signature: data.get_sig(&config.salt),
        data: data.clone(),
    })
}


#[get("/enc.json?<hwid>")]
fn get_enc_file(config: &State<KorepiConfig>, hwid: &str) -> Json<RawKeyFile> {
    let file = KeyFile {
        md5: config.md5.clone(),
        rsa_key: config.rsa_key.clone(),
        data: KeyData {
            user_id: 1337,
            hwid: hwid.to_string(),
            role: 31,
            cardstr: "crack saves lives".to_owned(),
            data_id: 1337,
            expiry_time: 1822477062,
        },
    };
    Json(file.export())
}

#[get("/md5verify/<hwid_uid>")]
fn md5verify(config: &State<KorepiConfig>, hwid_uid: &str) -> Json<KorepiResponse<KorepiMD5Response>> {
    let hwid_uid: Vec<&str> = hwid_uid.split(':').collect();
    let hwid = hwid_uid.first().unwrap().to_owned();
    let uid: u32 = hwid_uid.get(1).unwrap().parse().unwrap();
    let data = KorepiMD5Response {
        created_by: None,
        creation_time: "2024-02-01 13:37:00".to_owned(),
        updated_by: "anonymousUser".to_owned(),
        update_time: "2024-02-20 13:37:00".to_owned(),
        deletion_flag: 0,
        remark: "CrackPipe".to_owned(),
        id: uid,
        role_value: 31,
        card_key: None,
        expiry_time: "2069-04-20 13:37:00".to_owned(),
        last_login_time: "2024-02-20 13:37:00".to_owned(),
        hwid: hwid.to_owned(),
        file_md5: config.md5.clone(),
        reset_time: None,
        reset_num: 4,
        pause_time: None,
        status: 0,
    };

    Json(KorepiResponse {
        msg: "操作成功".to_owned(),
        signature: data.get_sig(&config.salt),
        data,
        code: 200,
    })
}

#[derive(Serialize, Debug)]
pub struct KorepiResponse<T> {
    msg: String,
    code: u16,
    data: T,
    signature: String,
}

#[derive(Serialize, Deserialize, Debug, Checksum, Clone)]
#[serde(crate = "rocket::serde")]
struct KorepiUpdateDiff {
    added_features: Vec<String>,
    deleted_features: Vec<String>,
    total_size: String,
}

#[derive(Serialize, Deserialize, Debug, Checksum, Clone)]
#[serde(crate = "rocket::serde")]
pub struct KorepiChangelogResponse {
    latest_version: String,
    update_required: bool,
    update_url: String,
    #[serde(rename = "announcement")]
    title: String,
    updated_by: String,
    updated_at: String,
    update_diff: KorepiUpdateDiff,
    compatible_versions: Vec<String>,
}

#[derive(Serialize, Debug, Checksum)]
pub struct KorepiMD5Response {
    #[serde(rename = "createBy")]
    created_by: Option<String>,
    #[serde(rename = "createTime")]
    creation_time: String,
    #[serde(rename = "updateBy")]
    updated_by: String,
    #[serde(rename = "updateTime")]
    update_time: String,
    #[serde(rename = "delFlag")]
    deletion_flag: u8,
    remark: String,
    id: u32,
    #[serde(rename = "roleValue")]
    role_value: u8,
    #[serde(rename = "cardKey")]
    card_key: Option<String>,
    #[serde(rename = "expiryTime")]
    expiry_time: String,
    #[serde(rename = "lastLoginTime")]
    last_login_time: String,
    hwid: String,
    #[serde(rename = "fileMd5")]
    file_md5: String,
    #[serde(rename = "resetTime")]
    reset_time: Option<String>,
    #[serde(rename = "resetNum")]
    reset_num: u32,
    #[serde(rename = "pauseTime")]
    pause_time: Option<String>,
    status: u8,
}

#[derive(Deserialize, Debug)]
#[serde(crate = "rocket::serde")]
struct KorepiConfig {
    enabled: Option<bool>,
    rsa_key: String,
    md5: String,
    salt: String,
    changelog: KorepiChangelogResponse,
}

#[derive(Deserialize, Debug)]
struct Config {
    korepi: KorepiConfig,
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
    if conf.korepi.enabled.is_none() || !conf.korepi.enabled.unwrap() {
        rocket
    } else {
        rocket.mount("/", routes![md5verify, get_enc_file, get_changelog]).mount("/prod-api/online/subscribe/", routes![md5verify]).manage(conf.korepi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_key_test() {
        let raw_key: RawKeyFile = from_str("{\"encrypted.dat\":\"ogGfKOmClVjH+b/fsfryNXwFOoZwvcX+RnQfRv6uhHKVR1odbdjDIfSub/xseR3fBIToOh8pzMDsX/HlEUYLB28MLYj+45TrLYweJV+41hQCx26AFJ3OzqBwvh3pV+G1oixBsm0GM8TV23RM8XRiXzCyQSyvE/ozXXMNQn2gLp6yJozE5YnvW5n7jBECA67PP29u7S0yzkXAorp1eOtYR2rx+HozHIs9y71jXhRd7MOqPeWBy4LS7SAu6NJ42pLmXB6mZU+KyjCiepjRqxjFjdpbda4DyrNutgZE+xh43oyaAiOJaGCDPXU59Qt03Yzt0LldZ/iTzeCPF5mNNPQdow==\",\"Encrypted.md5\":\"TzWiN0rbn9+TnQ==\",\"privatekey_pkcs1.pem.enc\":\"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\"}").unwrap();
        assert_eq!(String::from_utf8(raw_key.get_key()).unwrap(), "0c527fd6a170bbe103825feb1f3fc00c");
        assert_eq!(raw_key.get_rsa_key().unwrap(), "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0SxoW83nU4qAbHXqjhalMiU62ae79Ayv/EAmVfJEeCymJIpv\ntTqoPr99MBMDMHPxqqW1TgapD0bdAoU0vBpxG5INKIQnVi1ZE0YPP1GKUXN4nchM\n31a9NqG4mdWXtpD/jTt40Tpxn/zaj/5kDCuPo+iKQqwzKnE27Fyi0USLK82PfwCN\n0KlA4hmHUgB0UD+eG3VSlfHuU4ZITKqwEZFywREoekljDot8noMOQiBo0NgqmkLL\nK2WQ2TaTSm3A/E6d7FI+HrdPdl/GmMdTF1tflr1yMFQ1eAdOJqnmM5YxCv4FsU2q\npZFFXNEbnjJ+mx549LMUWBUeRjOwZ8zXUWxdoQIDAQABAoIBAD65522oWHd38D0W\nO0lyxwU7nuNIZpev+lJV1mktppS3JveMQCWDupJekCcLfIhaLJ105eLJIod/Q6WO\n1pqV/1c6PBHrV3SDUtPxzX66cBUu4HvIZi0PcNxiMN6I698Gqmvq6rcrpIlKpSxL\nKCtyILgRcuy9gPZ4TvUgbn785BM1Hby1LwNLPs9fhyl6QZZq4eTgyH5iGNIoDlhf\nDZkyj2WbqQ9tsVS/lFPV9B0eexfTLsEYT179vTyUEwJLgcteAu7c8asC+1XU3Mer\nHbXedC0vytNoGBCo1dg4QYeSgN6DKbhhLqrQY9ibR1LZv91j5fskUIiqQf3wgANs\nTilkB/ECgYEA7eLKFAXbyxs1BRV0mUcu0f1DlQJGJGZoyWMe9RMxMNwaM3PcmkAa\ndWE8nmLvLoMz8+5sw7BQ0ZVxgfDVVld0MnwnsJOMlLbPj3oBz0SLbZbNFrIX6jrt\nK2hcjVFn/YFssYAzGtUWB9TtOFdn38K5Pj0vfDOnSIj1ngNRC4WvaRUCgYEA4Rnq\nLE6sqMQCbChJEgkSkJedJem2jwGep7Dt/GgvJEIPjfZT+RaKpkFf6qDAPMmKi3eF\n1chc5SqPeJ2E7bM/3L1szytQKWTBqsVqHpyVOTe0IAAybVS4Mx3ICtjTzuKgRERY\nLJUVBEgWU0xnnRJqlAXIjuTkE47dDgehTafwrV0CgYBsm2tJQvd7Pluxi38lb9NX\nefq98EDX442ZzFBY8b82oHax4QbpwbSSvKcxZNfwc2RnzQYJPdlYJpOhELRF7D2X\nwwlX27WGPAR9a+WhnJjPmtbdsseqX+biN45x0qXYnptiWrZ6XKjnQHZhj75T8ZIj\ncUnZubd5LVZ+IuOAkDNqlQKBgH77SXiZIRlLCTrONvovmANtI79BajSd60wZqQbc\nFsvTYEbrEE/RgYFsG5mV+RvRbZBjamJA1vaH3ctiwJv+pCX3zavIeT4AkqetGcIO\n/rb6T2hF9CxswERFppVH36Qzf8lC7KKpruNtbvqqfUDEJM8/u/Wv9WF7FARYFYxj\nEogZAoGBAMNI6WOB/u4vm5QpJVW+p33xyJJTmVTmzCFXCRsOvC0gDwBZcKGe4BIR\nE7CyLasw3HG9IhZYOi/KoX+UQrcAOcRPAsJmlqiQxu2qskX81AiOkhPEBprVRhj3\nVqquzXQuHpi/UwwiVoBX0Qi1/bWI1t5krlF4Me17cT6hffD0N/Qr\n-----END RSA PRIVATE KEY-----\n");
        let data = raw_key.get_data().unwrap();
        assert_eq!(data.user_id, 1337);
        assert_eq!(data.hwid, "We_dont_need_no_thought_control.");
        assert_eq!(data.role, 31);
        assert_eq!(data.cardstr, "micah-oc-b660c1bac51111ee84530242ac110002");
        assert_eq!(data.data_id, 1337);
    }

    #[test]
    fn keyfile_test() {
        let key: KeyFile = KeyFile::from_string("{\"encrypted.dat\":\"ogGfKOmClVjH+b/fsfryNXwFOoZwvcX+RnQfRv6uhHKVR1odbdjDIfSub/xseR3fBIToOh8pzMDsX/HlEUYLB28MLYj+45TrLYweJV+41hQCx26AFJ3OzqBwvh3pV+G1oixBsm0GM8TV23RM8XRiXzCyQSyvE/ozXXMNQn2gLp6yJozE5YnvW5n7jBECA67PP29u7S0yzkXAorp1eOtYR2rx+HozHIs9y71jXhRd7MOqPeWBy4LS7SAu6NJ42pLmXB6mZU+KyjCiepjRqxjFjdpbda4DyrNutgZE+xh43oyaAiOJaGCDPXU59Qt03Yzt0LldZ/iTzeCPF5mNNPQdow==\",\"Encrypted.md5\":\"TzWiN0rbn9+TnQ==\",\"privatekey_pkcs1.pem.enc\":\"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\"}".to_owned()).unwrap();
        assert_eq!(String::from_utf8(key.get_key()).unwrap(), "0c527fd6a170bbe103825feb1f3fc00c");
        assert_eq!(key.rsa_key, "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0SxoW83nU4qAbHXqjhalMiU62ae79Ayv/EAmVfJEeCymJIpv\ntTqoPr99MBMDMHPxqqW1TgapD0bdAoU0vBpxG5INKIQnVi1ZE0YPP1GKUXN4nchM\n31a9NqG4mdWXtpD/jTt40Tpxn/zaj/5kDCuPo+iKQqwzKnE27Fyi0USLK82PfwCN\n0KlA4hmHUgB0UD+eG3VSlfHuU4ZITKqwEZFywREoekljDot8noMOQiBo0NgqmkLL\nK2WQ2TaTSm3A/E6d7FI+HrdPdl/GmMdTF1tflr1yMFQ1eAdOJqnmM5YxCv4FsU2q\npZFFXNEbnjJ+mx549LMUWBUeRjOwZ8zXUWxdoQIDAQABAoIBAD65522oWHd38D0W\nO0lyxwU7nuNIZpev+lJV1mktppS3JveMQCWDupJekCcLfIhaLJ105eLJIod/Q6WO\n1pqV/1c6PBHrV3SDUtPxzX66cBUu4HvIZi0PcNxiMN6I698Gqmvq6rcrpIlKpSxL\nKCtyILgRcuy9gPZ4TvUgbn785BM1Hby1LwNLPs9fhyl6QZZq4eTgyH5iGNIoDlhf\nDZkyj2WbqQ9tsVS/lFPV9B0eexfTLsEYT179vTyUEwJLgcteAu7c8asC+1XU3Mer\nHbXedC0vytNoGBCo1dg4QYeSgN6DKbhhLqrQY9ibR1LZv91j5fskUIiqQf3wgANs\nTilkB/ECgYEA7eLKFAXbyxs1BRV0mUcu0f1DlQJGJGZoyWMe9RMxMNwaM3PcmkAa\ndWE8nmLvLoMz8+5sw7BQ0ZVxgfDVVld0MnwnsJOMlLbPj3oBz0SLbZbNFrIX6jrt\nK2hcjVFn/YFssYAzGtUWB9TtOFdn38K5Pj0vfDOnSIj1ngNRC4WvaRUCgYEA4Rnq\nLE6sqMQCbChJEgkSkJedJem2jwGep7Dt/GgvJEIPjfZT+RaKpkFf6qDAPMmKi3eF\n1chc5SqPeJ2E7bM/3L1szytQKWTBqsVqHpyVOTe0IAAybVS4Mx3ICtjTzuKgRERY\nLJUVBEgWU0xnnRJqlAXIjuTkE47dDgehTafwrV0CgYBsm2tJQvd7Pluxi38lb9NX\nefq98EDX442ZzFBY8b82oHax4QbpwbSSvKcxZNfwc2RnzQYJPdlYJpOhELRF7D2X\nwwlX27WGPAR9a+WhnJjPmtbdsseqX+biN45x0qXYnptiWrZ6XKjnQHZhj75T8ZIj\ncUnZubd5LVZ+IuOAkDNqlQKBgH77SXiZIRlLCTrONvovmANtI79BajSd60wZqQbc\nFsvTYEbrEE/RgYFsG5mV+RvRbZBjamJA1vaH3ctiwJv+pCX3zavIeT4AkqetGcIO\n/rb6T2hF9CxswERFppVH36Qzf8lC7KKpruNtbvqqfUDEJM8/u/Wv9WF7FARYFYxj\nEogZAoGBAMNI6WOB/u4vm5QpJVW+p33xyJJTmVTmzCFXCRsOvC0gDwBZcKGe4BIR\nE7CyLasw3HG9IhZYOi/KoX+UQrcAOcRPAsJmlqiQxu2qskX81AiOkhPEBprVRhj3\nVqquzXQuHpi/UwwiVoBX0Qi1/bWI1t5krlF4Me17cT6hffD0N/Qr\n-----END RSA PRIVATE KEY-----\n");
        assert_eq!(key.data.user_id, 1337);
        assert_eq!(key.data.hwid, "We_dont_need_no_thought_control.");
        assert_eq!(key.data.role, 31);
        assert_eq!(key.data.cardstr, "micah-oc-b660c1bac51111ee84530242ac110002");
        assert_eq!(key.data.data_id, 1337);
        let exported: RawKeyFile = key.export();
        println!("{:#?}", exported);
        assert_eq!(String::from_utf8(exported.get_key()).unwrap(), "0c527fd6a170bbe103825feb1f3fc00c");
        assert_eq!(exported.get_rsa_key().unwrap(), "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0SxoW83nU4qAbHXqjhalMiU62ae79Ayv/EAmVfJEeCymJIpv\ntTqoPr99MBMDMHPxqqW1TgapD0bdAoU0vBpxG5INKIQnVi1ZE0YPP1GKUXN4nchM\n31a9NqG4mdWXtpD/jTt40Tpxn/zaj/5kDCuPo+iKQqwzKnE27Fyi0USLK82PfwCN\n0KlA4hmHUgB0UD+eG3VSlfHuU4ZITKqwEZFywREoekljDot8noMOQiBo0NgqmkLL\nK2WQ2TaTSm3A/E6d7FI+HrdPdl/GmMdTF1tflr1yMFQ1eAdOJqnmM5YxCv4FsU2q\npZFFXNEbnjJ+mx549LMUWBUeRjOwZ8zXUWxdoQIDAQABAoIBAD65522oWHd38D0W\nO0lyxwU7nuNIZpev+lJV1mktppS3JveMQCWDupJekCcLfIhaLJ105eLJIod/Q6WO\n1pqV/1c6PBHrV3SDUtPxzX66cBUu4HvIZi0PcNxiMN6I698Gqmvq6rcrpIlKpSxL\nKCtyILgRcuy9gPZ4TvUgbn785BM1Hby1LwNLPs9fhyl6QZZq4eTgyH5iGNIoDlhf\nDZkyj2WbqQ9tsVS/lFPV9B0eexfTLsEYT179vTyUEwJLgcteAu7c8asC+1XU3Mer\nHbXedC0vytNoGBCo1dg4QYeSgN6DKbhhLqrQY9ibR1LZv91j5fskUIiqQf3wgANs\nTilkB/ECgYEA7eLKFAXbyxs1BRV0mUcu0f1DlQJGJGZoyWMe9RMxMNwaM3PcmkAa\ndWE8nmLvLoMz8+5sw7BQ0ZVxgfDVVld0MnwnsJOMlLbPj3oBz0SLbZbNFrIX6jrt\nK2hcjVFn/YFssYAzGtUWB9TtOFdn38K5Pj0vfDOnSIj1ngNRC4WvaRUCgYEA4Rnq\nLE6sqMQCbChJEgkSkJedJem2jwGep7Dt/GgvJEIPjfZT+RaKpkFf6qDAPMmKi3eF\n1chc5SqPeJ2E7bM/3L1szytQKWTBqsVqHpyVOTe0IAAybVS4Mx3ICtjTzuKgRERY\nLJUVBEgWU0xnnRJqlAXIjuTkE47dDgehTafwrV0CgYBsm2tJQvd7Pluxi38lb9NX\nefq98EDX442ZzFBY8b82oHax4QbpwbSSvKcxZNfwc2RnzQYJPdlYJpOhELRF7D2X\nwwlX27WGPAR9a+WhnJjPmtbdsseqX+biN45x0qXYnptiWrZ6XKjnQHZhj75T8ZIj\ncUnZubd5LVZ+IuOAkDNqlQKBgH77SXiZIRlLCTrONvovmANtI79BajSd60wZqQbc\nFsvTYEbrEE/RgYFsG5mV+RvRbZBjamJA1vaH3ctiwJv+pCX3zavIeT4AkqetGcIO\n/rb6T2hF9CxswERFppVH36Qzf8lC7KKpruNtbvqqfUDEJM8/u/Wv9WF7FARYFYxj\nEogZAoGBAMNI6WOB/u4vm5QpJVW+p33xyJJTmVTmzCFXCRsOvC0gDwBZcKGe4BIR\nE7CyLasw3HG9IhZYOi/KoX+UQrcAOcRPAsJmlqiQxu2qskX81AiOkhPEBprVRhj3\nVqquzXQuHpi/UwwiVoBX0Qi1/bWI1t5krlF4Me17cT6hffD0N/Qr\n-----END RSA PRIVATE KEY-----\n");
        let data = exported.get_data().unwrap();
        assert_eq!(data.user_id, 1337);
        assert_eq!(data.hwid, "We_dont_need_no_thought_control.");
        assert_eq!(data.role, 31);
        assert_eq!(data.cardstr, "micah-oc-b660c1bac51111ee84530242ac110002");
        assert_eq!(data.data_id, 1337);
    }
}
