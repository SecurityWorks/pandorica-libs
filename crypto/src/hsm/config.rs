use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Serialize, Deserialize)]
pub struct HsmSettings {
    pub provider: Cow<'static, str>,
    pub gcp: Option<GoogleCloudPlatformSettings>,
}

#[derive(Serialize, Deserialize)]
pub struct GoogleCloudPlatformSettings {
    pub project_id: Cow<'static, str>,
    pub location: Cow<'static, str>,
    pub key_ring: Cow<'static, str>,
    pub key: Cow<'static, str>,
}

impl Default for HsmSettings {
    fn default() -> Self {
        Self {
            provider: "gcp".into(),
            gcp: None,
        }
    }
}
