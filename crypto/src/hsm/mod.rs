use crate::hsm::gcp::Gcp;
use anyhow::format_err;
use secret_vault_value::SecretValue;
use shared::error::{EmptyResult, OperationResult};
use singleton::{Singleton, SingletonInit};

pub use crate::hsm::config::GoogleCloudPlatformSettings;
pub use crate::hsm::config::HsmSettings;

mod config;
mod gcp;

#[derive(Default)]
enum Provider {
    #[default]
    Gcp,
}

#[derive(Default, Singleton)]
pub struct HsmProvider {
    provider: Provider,
    gcp: OnceCell<Gcp>,
}

impl HsmProvider {
    pub async fn init_provider(&mut self, settings: &HsmSettings) -> EmptyResult {
        match settings.provider.as_ref() {
            "gcp" => {
                self.provider = Provider::Gcp;
                self.gcp = OnceCell::with_value(Gcp::init(settings.gcp.as_ref().unwrap()).await?);
            }
            _ => {
                return Err(format_err!("Invalid HSM provider: {}", settings.provider).into());
            }
        }

        Ok(())
    }

    pub async fn encrypt_envelope(
        &self,
        plaintext: SecretValue,
        key: &str,
    ) -> OperationResult<Vec<u8>> {
        match self.provider {
            Provider::Gcp => {
                self.gcp
                    .get()
                    .unwrap()
                    .encrypt_envelope(plaintext, key)
                    .await
            }
        }
    }

    pub async fn decrypt_envelope(
        &self,
        ciphertext: &[u8],
        key: &str,
    ) -> OperationResult<SecretValue> {
        match self.provider {
            Provider::Gcp => {
                self.gcp
                    .get()
                    .unwrap()
                    .decrypt_envelope(ciphertext, key)
                    .await
            }
        }
    }

    pub async fn generate_random_bytes(&self, size: u32) -> OperationResult<Vec<u8>> {
        match self.provider {
            Provider::Gcp => self.gcp.get().unwrap().generate_random_bytes(size).await,
        }
    }
}

impl SingletonInit<HsmProvider> for HsmProvider {
    fn init() -> HsmProvider {
        HsmProvider::default()
    }
}
