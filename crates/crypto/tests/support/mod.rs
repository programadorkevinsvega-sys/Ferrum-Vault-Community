use aws_lc_rs::aead::{Nonce, NonceSequence};
use aws_lc_rs::error::Unspecified;

#[derive(Debug)]
pub struct FixedNonce(pub [u8; 12]);

impl NonceSequence for FixedNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

pub fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input must have an even length");
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("valid hex");
            let low = (pair[1] as char).to_digit(16).expect("valid hex");
            ((high << 4) | low) as u8
        })
        .collect()
}
