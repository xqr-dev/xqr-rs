use jwt_simple::prelude::*;
use jwt_simple::Error;
use serde_derive::{Deserialize, Serialize};

/// Represents the extended quick response (XQR) code, encapsulating the JWT token.
#[derive(Debug, Serialize, Deserialize)]
pub struct XQR {
    pub token: String,
}

/// Converts the XQR structure to a String representation.
impl ToString for XQR {
    fn to_string(&self) -> String {
        self.token.clone()
    }
}

/// Converts a String to an XQR structure.
impl From<String> for XQR {
    fn from(s: String) -> Self {
        XQR { token: s }
    }
}

/// Defines the custom claims to be used in the JWT token, including `kid` and `value`.
#[derive(Debug, Serialize, Deserialize)]
pub struct XQRClaims {
    kid: String,
    value: String,
}

/// Encodes a value into a JWT token using a private key in PEM format.
///
/// # Arguments
///
/// * `private_key_pem` - The private key in PEM format.
/// * `value` - The value to encode into the JWT token.
/// * `kid` - The key ID, typically a URL that identifies the key.
///
/// # Returns
///
/// A Result containing the XQR structure or an error if the operation fails.
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

/// Decodes a JWT token contained in an XQR structure using a public key in PEM format.
///
/// # Arguments
///
/// * `public_key_pem` - The public key in PEM format.
/// * `xqr` - The XQR structure containing the JWT token to decode.
///
/// # Returns
///
/// A Result containing the decoded value as a String or an error if the operation fails.
pub fn decode(public_key_pem: &str, xqr: XQR) -> Result<String, Error> {
    let public_key = ES256PublicKey::from_pem(public_key_pem)?;
    let token = xqr.token;
    let claims = public_key.verify_token::<XQRClaims>(&token, None)?.custom;

    Ok(claims.value)
}

/// Generates a new ECDSA (ES256) key pair for use with JWT tokens.
///
/// # Returns
///
/// The generated ES256 key pair.
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
