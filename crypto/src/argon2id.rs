use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand_core::OsRng;
use secret_vault_value::SecretValue;
use shared::error::OperationResult;

pub struct Argon2id;

impl Argon2id {
    pub fn generate_hash(plaintext: &SecretValue) -> OperationResult<Vec<u8>> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = plaintext
            .exposed_in_as_zvec(|p| Argon2::default().hash_password(p.as_slice(), &salt))?;
        Ok(hash.serialize().as_bytes().into())
    }

    pub fn verify_hash(plaintext: &SecretValue, hash: &[u8]) -> OperationResult<bool> {
        let password_string = std::str::from_utf8(hash)?;
        let password_hash = PasswordHash::new(password_string)?;
        Ok(plaintext.exposed_in_as_zvec(|p| {
            Argon2::default()
                .verify_password(p.as_slice(), &password_hash)
                .is_ok()
        }))
    }

    pub fn derive_key(plaintext: &SecretValue, length: usize) -> OperationResult<SecretValue> {
        let salt = SaltString::generate(&mut OsRng);
        let output_key: Result<Vec<u8>, anyhow::Error> = plaintext.exposed_in_as_zvec(|p| {
            let mut output_key = vec![0u8; length];
            Argon2::default().hash_password_into(
                p.as_slice(),
                salt.as_str().as_bytes(),
                &mut output_key,
            )?;
            Ok(output_key)
        });
        Ok(output_key?.into())
    }
}
