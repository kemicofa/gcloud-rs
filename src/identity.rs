use std::{
    str::FromStr,
    time::{Duration, SystemTime},
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::consts::{DEFAULT_REFRESH_PARAMS, DEFAULT_TOKEN_HOST};

#[derive(Serialize, Deserialize)]
pub struct GCloudIdentity {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    created_at: SystemTime,
}

impl GCloudIdentity {
    pub fn new(access_token: String, refresh_token: String, expires_in: u64) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_in,
            created_at: SystemTime::now(),
        }
    }

    /// Method that determines if the access_token is expired or about to expire
    pub fn is_expired(&self) -> bool {
        let duration = Duration::from_secs(self.expires_in);
        let threshold_duration = duration - (duration / 9); // 90% of the expires_in value
        self.created_at.elapsed().unwrap() > threshold_duration
    }

    pub fn get_refresh_access_token_uri(&mut self) -> Result<String, &str> {
        let mut url =
            Url::from_str(DEFAULT_TOKEN_HOST).expect("Unable to generate url from token base url");

        let mut encoded_params = form_urlencoded::Serializer::new(String::new());

        for (key, value) in DEFAULT_REFRESH_PARAMS {
            encoded_params.append_pair(key, value);
        }

        encoded_params.append_pair("refresh_token", self.refresh_token.as_str());
        url.set_query(Some(encoded_params.finish().as_str()));
        Ok(url.to_string())
    }

    pub fn get_token(&self) -> Result<String, String> {
        if self.is_expired() {
            return Err("Token is expired".to_string());
        }
        Ok(self.access_token.clone())
    }
}
