use jwt_simple::prelude::*;
use jwt_simple::Error;
use reqwest;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

/// Represents the extended quick response (XQR) code, encapsulating the JWT token.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct XQR {
    pub token: String,
}

impl XQR {
    /// Returns the Key ID (kid) from the JWT token contained in the XQR structure.
    ///
    /// # Returns
    ///
    /// An Option containing the Key ID as a string if present, or None if not found.
    pub fn get_kid(&self) -> Option<String> {
        match Token::decode_metadata(&self.token) {
            Ok(metadata) => metadata.key_id().map(|s| s.to_string()),
            Err(_) => None,
        }
    }
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
    value: String,
}

/// Encodes a value into a JWT token using a private key in PEM format.
///
/// # Arguments
///
/// * `private_key_pem` - The private key in PEM format.
/// * `value` - The value to encode into the JWT token.
/// * `kid` - The key ID, typically a URL that identifies the key.
/// * `valid_for` - The duration for which the token is valid. If not specified, the XQR will be valid forever.
///
/// # Returns
///
/// A Result containing the XQR structure or an error if the operation fails.
pub fn encode(
    private_key_pem: &str,
    value: &str,
    kid: &str,
    valid_for: Option<Duration>,
) -> Result<XQR, Error> {
    let key_pair = ES256KeyPair::from_pem(private_key_pem)?;
    let key_pair = key_pair.with_key_id(kid);
    let initial_duration = match valid_for {
        Some(duration) => duration,
        // with_custom_claims requires a non-None duration, so we use 0 if valid_for is None.
        // After creating the claims, we'll set the expires_at value to None.
        None => Duration::from_hours(0),
    };
    let mut claims = Claims::with_custom_claims(
        XQRClaims {
            value: value.to_string(),
        },
        initial_duration,
    );
    if valid_for.is_none() {
        claims.expires_at = None;
    }
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

/// Fetches the public key based on the key ID.
///
/// # Arguments
///
/// * `key_id` - The key ID in the format "example.com#123".
///
/// # Returns
///
/// A Result containing the public key as a string in PEM format or an error if the operation fails.
pub fn fetch_public_key(key_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Extract the URL from the key_id
    let url_parts: Vec<&str> = key_id.split('#').collect();
    let url = format!("https://{}/.well-known/jwks.json", url_parts[0]);

    // Make the HTTP request
    let response = reqwest::blocking::get(&url)?;
    let jwks: Value = response.json()?;

    // Iterate through the keys to find the matching kid
    if let Some(keys) = jwks["keys"].as_array() {
        for key in keys {
            if key["kid"].as_str() == Some(key_id) {
                // Extract and return the public key in your desired format (e.g., PEM)
                // The actual extraction may vary depending on the JWKS structure
                return Ok(key["x5c"].as_array().unwrap()[0]
                    .as_str()
                    .unwrap()
                    .to_string());
            }
        }
    }

    Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Key ID not found",
    )))
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

        let encoded_xqr = encode(&private_key, value, kid, None).unwrap();
        let decoded_value = decode(&public_key, encoded_xqr).unwrap();

        assert_eq!(decoded_value, value);
    }

    #[test]
    fn decode_with_wrong_pub_key_fails() {
        let key_pair = generate_key_pair();
        let private_key = key_pair.to_pem().unwrap();
        let public_key = generate_key_pair().public_key().to_pem().unwrap();
        let value = "value";
        let kid = "example.com#123";

        let encoded_xqr = encode(&private_key, value, kid, None).unwrap();
        let decoded_value = decode(&public_key, encoded_xqr);

        assert!(decoded_value.is_err());
    }

    #[test]
    fn get_kid_test() {
        let key_pair = generate_key_pair();
        let private_key = key_pair.to_pem().unwrap();
        let value = "value";
        let kid = "example.com#123";

        let encoded_xqr = encode(&private_key, value, kid, None).unwrap();

        assert_eq!(encoded_xqr.get_kid().unwrap(), kid);
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

    #[test]
    fn xqr_to_string_ergonomics() {
        let key_pair = generate_key_pair();
        let private_key = key_pair.to_pem().unwrap();
        let value = "value";
        let kid = "example.com#123";

        let encoded_xqr = encode(&private_key, value, kid, None).unwrap();

        assert_eq!(encoded_xqr.to_string(), encoded_xqr.token);
    }

    #[test]
    fn xqr_from_string_ergonomics() {
        let key_pair = generate_key_pair();
        let private_key = key_pair.to_pem().unwrap();
        let value = "value";
        let kid = "example.com#123";

        let encoded_xqr = encode(&private_key, value, kid, None).unwrap();
        let encoded_xqr_string = encoded_xqr.to_string();

        assert_eq!(XQR::from(encoded_xqr_string), encoded_xqr);
    }

    #[test]
    fn expiration_is_not_set_when_valid_for_is_none() {
        let key_pair = generate_key_pair();
        let private_key = key_pair.to_pem().unwrap();
        let pub_key = key_pair.public_key();
        let value = "value";
        let kid = "example.com#123";

        let encoded_xqr = encode(&private_key, value, kid, None).unwrap();
        let claims = pub_key
            .verify_token::<XQRClaims>(&encoded_xqr.token, None)
            .unwrap();

        assert!(claims.expires_at.is_none());
    }

    #[test]
    fn expiration_is_set_when_valid_for_is_not_none() {
        let key_pair = generate_key_pair();
        let private_key = key_pair.to_pem().unwrap();
        let pub_key = key_pair.public_key();
        let value = "value";
        let kid = "example.com#123";
        let valid_for = Duration::from_secs(60);

        let encoded_xqr = encode(&private_key, value, kid, Some(valid_for)).unwrap();
        let claims = pub_key
            .verify_token::<XQRClaims>(&encoded_xqr.token, None)
            .unwrap();

        assert!(claims.expires_at.is_some());
    }
}
