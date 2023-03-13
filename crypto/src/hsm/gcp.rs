use crate::hsm::GoogleCloudPlatformSettings;
use gcloud_sdk::google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient;
use gcloud_sdk::google::cloud::kms::v1::{DecryptRequest, GenerateRandomBytesRequest};
use gcloud_sdk::proto_ext::kms::EncryptRequest;
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use once_cell::sync::OnceCell;
use secret_vault_value::SecretValue;
use shared::error::OperationResult;
use tonic::metadata::MetadataValue;

pub struct Gcp {
    kms_service: OnceCell<GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>>,
    location: String,
    keyring: String,
}

impl Gcp {
    pub async fn init(settings: &GoogleCloudPlatformSettings) -> OperationResult<Self> {
        let kms_service = OnceCell::from(
            GoogleApi::from_function(
                KeyManagementServiceClient::new,
                "https://cloudkms.googleapis.com",
                None,
            )
            .await?,
        );

        let location = format!(
            "projects/{}/locations/{}",
            settings.project_id, settings.location
        );

        let keyring = format!("{}/keyRings/{}/cryptoKeys", location, settings.key_ring);

        Ok(Self {
            kms_service,
            location,
            keyring,
        })
    }

    pub async fn encrypt_envelope(
        &self,
        plaintext: SecretValue,
        key: &str,
    ) -> OperationResult<Vec<u8>> {
        let key = format!("{}/{}", self.keyring.clone(), key);

        let mut encrypt_request = tonic::Request::new(EncryptRequest {
            name: key.clone(),
            plaintext,
            additional_authenticated_data: vec![],
            plaintext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        });

        encrypt_request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!("name={}", key)).unwrap(),
        );

        let response = &self
            .kms_service
            .get()
            .unwrap()
            .get()
            .encrypt(encrypt_request)
            .await?;

        let response = response.get_ref().clone();

        Ok(response.ciphertext)
    }

    pub async fn decrypt_envelope(
        &self,
        ciphertext: &[u8],
        key: &str,
    ) -> OperationResult<SecretValue> {
        let key = format!("{}/{}", self.keyring.clone(), key);

        let mut decrypt_request = tonic::Request::new(DecryptRequest {
            name: key.clone(),
            ciphertext: ciphertext.into(),
            additional_authenticated_data: vec![],
            ciphertext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        });

        decrypt_request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!("name={}", key)).unwrap(),
        );

        let response = &self
            .kms_service
            .get()
            .unwrap()
            .get()
            .decrypt(decrypt_request)
            .await?;

        let response = response.get_ref().clone();

        Ok(response.plaintext)
    }

    pub async fn generate_random_bytes(&self, size: u32) -> OperationResult<Vec<u8>> {
        let mut generate_random_bytes_request = tonic::Request::new(GenerateRandomBytesRequest {
            location: self.location.clone(),
            length_bytes: size as i32,
            protection_level: 2,
        });

        generate_random_bytes_request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!(
                "name={}",
                self.location.clone()
            ))
            .unwrap(),
        );

        let response = &self
            .kms_service
            .get()
            .unwrap()
            .get()
            .generate_random_bytes(generate_random_bytes_request)
            .await?;

        let response = response.get_ref().clone();

        Ok(response.data)
    }
}
