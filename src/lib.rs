use base64::engine::general_purpose::NO_PAD;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use base64::{alphabet, Engine as _};
use jwtk::jwk::WithKid;
use jwtk::{decode_without_verify, ecdsa, sign, verify, HeaderAndClaims};
use reqwest;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;

const NO_PAD_TRAILING_BITS: GeneralPurposeConfig = NO_PAD.with_decode_allow_trailing_bits(true);
const URL_SAFE_NO_PAD: GeneralPurpose =
    GeneralPurpose::new(&alphabet::URL_SAFE, NO_PAD_TRAILING_BITS);

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
        match decode_without_verify::<XQRClaims>(&self.token) {
            Ok(header) => header.header().kid.clone().map(|s| s.to_string()),
            Err(_) => None,
        }
    }

    /// Returns the value from the JWT token contained in the XQR structure.
    ///
    /// # Returns
    ///
    /// An Option containing the value as a string if present, or None if not found.
    pub fn get_iss(&self) -> Option<String> {
        match decode_without_verify::<XQRClaims>(&self.token) {
            Ok(header) => header.claims().iss.clone().map(|s| s.to_string()),
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
    iss: &str,
    valid_for: Option<std::time::Duration>,
) -> jwtk::Result<XQR> {
    let private_key = ecdsa::EcdsaPrivateKey::from_pem(private_key_pem.as_ref())?;
    let private_key = WithKid::new_with_thumbprint_id(private_key)?;

    let mut claims = HeaderAndClaims::new_dynamic();
    let claims = claims
        .insert("value", value)
        .set_iss(iss)
        .set_iat_now()
        .set_nbf_from_now(std::time::Duration::from_secs(0));
    if valid_for.is_some() {
        claims.set_exp_from_now(valid_for.unwrap());
    }

    let token = sign(claims, &private_key)?;
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
pub fn decode(public_key_pem: &str, xqr: &XQR) -> jwtk::Result<String> {
    let public_key = ecdsa::EcdsaPublicKey::from_pem(public_key_pem.as_ref())?;
    let verified = verify::<XQRClaims>(&xqr.token, &public_key)?;
    Ok(verified.claims().extra.value.clone())
}

/// Fetches the public key based on the key ID.
///
/// # Arguments
///
/// * `issuer` - The issuer URL (e.g. https://example.com, https://demo.xqr.dev).
/// * `key_id` - The key ID in the format "example.com#123".
///
/// # Returns
///
/// A Result containing the public key as a string in PEM format or an error if the operation fails.
pub fn fetch_public_key(issuer: &str, key_id: &str) -> Result<String, Box<dyn Error>> {
    let domain = url::Url::parse(issuer)?;
    let domain = domain.host_str().unwrap();
    let url = format!("https://{}/.well-known/jwks.json", domain);

    // Make the HTTP request
    let response = reqwest::blocking::get(&url)?;
    let jwks: Value = response.json()?;

    // Iterate through the keys to find the matching kid
    if let Some(keys) = jwks["keys"].as_array() {
        for key in keys {
            if key["kid"].as_str() == Some(key_id) {
                let pub_key = ecdsa::EcdsaPublicKey::from_coordinates(
                    &URL_SAFE_NO_PAD.decode(key["x"].as_str().unwrap())?,
                    &URL_SAFE_NO_PAD.decode(key["y"].as_str().unwrap())?,
                    ecdsa::EcdsaAlgorithm::ES256,
                )?;
                return Ok(pub_key.to_pem()?);
            }
        }
    }

    Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Key ID not found",
    )))
}

/// Generates a new ECDSA (ES256) private key for use with JWT tokens.
///
/// # Returns
///
/// The generated ES256 private key.
pub fn generate_key() -> jwtk::Result<ecdsa::EcdsaPrivateKey> {
    ecdsa::EcdsaPrivateKey::generate(ecdsa::EcdsaAlgorithm::ES256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn encode_decode_test() {
        let key = generate_key().unwrap();
        let private_key = key.private_key_to_pem_pkcs8().unwrap();
        let public_key = key.public_key_to_pem().unwrap();

        let encoded_xqr = encode(&private_key, "value", "https://example.com", None).unwrap();
        let decoded_value = decode(&public_key, &encoded_xqr).unwrap();

        assert_eq!(decoded_value, "value");
    }

    #[test]
    fn decode_with_wrong_pub_key_fails() {
        let key = generate_key().unwrap();
        let private_key = key.private_key_to_pem_pkcs8().unwrap();
        let public_key = generate_key().unwrap().public_key_to_pem().unwrap();

        let encoded_xqr = encode(&private_key, "value", "https://example.com", None).unwrap();
        let decoded_value = decode(&public_key, &encoded_xqr);

        assert!(decoded_value.is_err());
    }

    #[test]
    fn get_kid_test() {
        let key = generate_key().unwrap();
        let private_key = key.private_key_to_pem_pkcs8().unwrap();

        let encoded_xqr = encode(&private_key, "value", "https://example.com", None).unwrap();

        assert!(encoded_xqr.get_kid().is_some());
    }

    #[test]
    fn get_iss_test() {
        let key = generate_key().unwrap();
        let private_key = key.private_key_to_pem_pkcs8().unwrap();

        let encoded_xqr = encode(&private_key, "value", "https://example.com", None).unwrap();

        assert_eq!(encoded_xqr.get_iss().unwrap(), "https://example.com");
    }

    #[test]
    fn pem_serialization_test() {
        let key = generate_key().unwrap();
        let private_pem = key.private_key_to_pem_pkcs8().unwrap();
        let public_pem = key.public_key_to_pem().unwrap();

        // Verify that the PEM strings contain the correct headers
        assert!(private_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(private_pem.contains("-----END PRIVATE KEY-----"));
        assert!(public_pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(public_pem.contains("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn xqr_to_string_ergonomics() {
        let key = generate_key().unwrap();
        let private_key = key.private_key_to_pem_pkcs8().unwrap();

        let encoded_xqr = encode(&private_key, "value", "https://example.com", None).unwrap();

        assert_eq!(encoded_xqr.to_string(), encoded_xqr.token);
    }

    #[test]
    fn xqr_from_string_ergonomics() {
        let key = generate_key().unwrap();
        let private_key = key.private_key_to_pem_pkcs8().unwrap();

        let encoded_xqr = encode(&private_key, "value", "https://example.com", None).unwrap();
        let encoded_xqr_string = encoded_xqr.to_string();

        assert_eq!(XQR::from(encoded_xqr_string), encoded_xqr);
    }

    #[test]
    fn expiration_is_not_set_when_valid_for_is_none() {
        let key = generate_key().unwrap();
        let private_key = key.private_key_to_pem_pkcs8().unwrap();
        let public_key = key.public_key_to_pem().unwrap();
        let public_key = ecdsa::EcdsaPublicKey::from_pem(public_key.as_ref()).unwrap();

        let encoded_xqr = encode(&private_key, "value", "https://example.com", None).unwrap();
        let claims = verify::<XQRClaims>(&encoded_xqr.token, &public_key).unwrap();

        assert!(claims.claims().exp.is_none());
    }

    #[test]
    fn expiration_is_set_when_valid_for_is_not_none() {
        let key = generate_key().unwrap();
        let private_key = key.private_key_to_pem_pkcs8().unwrap();
        let public_key = key.public_key_to_pem().unwrap();
        let public_key = ecdsa::EcdsaPublicKey::from_pem(public_key.as_ref()).unwrap();

        let encoded_xqr = encode(
            &private_key,
            "value",
            "https://example.com",
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        let claims = verify::<XQRClaims>(&encoded_xqr.token, &public_key).unwrap();

        assert!(claims.claims().exp.is_some());
    }
}
