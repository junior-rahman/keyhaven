// apps/desktop/src-tauri/src/handshake.rs
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

fn mac(token: &[u8], label: &str, client_nonce: &[u8], core_nonce: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(token).expect("HMAC takes any key length");
    mac.update(label.as_bytes());
    mac.update(client_nonce);
    mac.update(core_nonce);
    mac
}

/// What the core sends first, proving it holds the pairing token without revealing it.
pub fn core_proof(token: &[u8], client_nonce: &[u8], core_nonce: &[u8]) -> [u8; 32] {
    mac(token, "kh/v1/core", client_nonce, core_nonce).finalize().into_bytes().into()
}

/// Constant-time check of the client's answer. A wrong or replayed proof ends the connection.
pub fn client_proof_ok(token: &[u8], client_nonce: &[u8], core_nonce: &[u8], claimed: &[u8]) -> bool {
    mac(token, "kh/v1/client", client_nonce, core_nonce).verify_slice(claimed).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_typescript_client() {
        let (cn, sn, token) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        assert_eq!(
            hex::encode(core_proof(&token, &cn, &sn)),
            "04015b7e21caea2a04b258c423d5984c7700acf37e50286387300d73e9f703bd"
        );
        let client = hex::decode("ec822164700a79943961e68ad3d3ced9a4822b3a380f94e1cb966986e1dddb95").unwrap();
        assert!(client_proof_ok(&token, &cn, &sn, &client));
        assert!(!client_proof_ok(&token, &cn, &[9u8; 32], &client)); // a proof replayed against a fresh nonce
        assert!(!client_proof_ok(&[4u8; 32], &cn, &sn, &client)); // another client's token
    }
}
