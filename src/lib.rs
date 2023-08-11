use jwt_simple::prelude::*;
use jwt_simple::Error;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct XQR {
    pub token: String,
}

impl ToString for XQR {
    fn to_string(&self) -> String {
        self.token.clone()
    }
}

impl From<String> for XQR {
    fn from(s: String) -> Self {
        XQR { token: s }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XQRClaims {
    kid: String,
    value: String,
}

pub fn encode(private_key_pem: &str, value: &str, kid: &str) -> Result<XQR, Error> {
    let key_pair = ES256KeyPair::from_pem(private_key_pem)?;
    let claims = Claims::with_custom_claims(
        XQRClaims {
            kid: kid.to_string(),
            value: value.to_string(),
        },
        Duration::from_hours(2),
    );
    let token = key_pair.sign(claims)?;

    Ok(XQR { token })
}

pub fn decode(public_key_pem: &str, xqr: XQR) -> Result<String, Error> {
    let public_key = ES256PublicKey::from_pem(public_key_pem)?;
    let token = xqr.token;
    let claims = public_key.verify_token::<XQRClaims>(&token, None)?.custom;

    Ok(claims.value)
}

pub fn generate_key_pair() -> ES256KeyPair {
    ES256KeyPair::generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_test() {
        let key_pair = generate_key_pair();
        let private_key = key_pair.to_pem().unwrap();
        let public_key = key_pair.public_key().to_pem().unwrap();
        let value = "value";
        let kid = "example.com#123";

        let encoded_xqr = encode(&private_key, value, kid).unwrap();
        let decoded_value = decode(&public_key, encoded_xqr).unwrap();

        assert_eq!(decoded_value, value);
    }

    #[test]
    fn pem_serialization_test() {
        let key_pair = generate_key_pair();

        // Convert keys to PEM
        let private_pem = key_pair.to_pem().unwrap();
        let public_pem = key_pair.public_key().to_pem().unwrap();

        // Verify that the PEM strings contain the correct headers
        assert!(private_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(private_pem.contains("-----END PRIVATE KEY-----"));
        assert!(public_pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(public_pem.contains("-----END PUBLIC KEY-----"));
    }
}
