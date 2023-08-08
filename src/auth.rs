use std::{collections::HashMap, str::FromStr};

use consts::{CLOUDSDK_EXTERNAL_ACCOUNT_SCOPES, DEFAULT_AUTH_HOST, DEFAULT_AUTH_PARAMS};
use state::generate_random_state;
use url::Url;

use crate::{
    consts::{self, DEFAULT_TOKEN_HOST, DEFAULT_TOKEN_PARAMS},
    identity::GCloudIdentity,
    state,
    utils::append_query_params_to_url,
};

pub struct GCloudAuth {
    state: String,
}

impl Default for GCloudAuth {
    fn default() -> Self {
        Self {
            state: generate_random_state(),
        }
    }
}

impl GCloudAuth {
    /// Step one of authenticating a user oauth
    ///
    /// Use this URI to redirect the user to a browser to authenticate
    /// https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient
    pub fn get_login_uri(&self, redirect_uri: &str) -> String {
        validate_redirect_uri(redirect_uri);

        let base_auth_url =
            Url::from_str(DEFAULT_AUTH_HOST).expect("Unable to init gcloud auth url from base");

        let mut auth_params: Vec<(&str, &str)> = DEFAULT_AUTH_PARAMS.to_vec();
        auth_params.push(("redirect_uri", redirect_uri));

        let scopes_string = CLOUDSDK_EXTERNAL_ACCOUNT_SCOPES.to_vec().join(" ");
        auth_params.push(("scope", scopes_string.as_str()));

        auth_params.push(("state", self.state.as_str()));

        let uri = append_query_params_to_url(base_auth_url, auth_params);

        uri.to_string()
    }

    /// Step two of authenticating a user oauth
    ///
    /// Using the callback uri after the user authenticated using the step one uri
    /// This will generate a token uri to be called with a POST request to exchange
    /// the code for a token
    /// https://developers.google.com/identity/protocols/oauth2/web-server#redirecting
    pub fn get_token_uri(&self, callback_uri: &str, redirect_uri: &str) -> Result<String, String> {
        validate_redirect_uri(redirect_uri);

        let callback_url = match Url::parse(callback_uri) {
            Ok(url) => url,
            Err(err) => return Err(format!("Failed parsing gcloud callback url: {err}")),
        };

        let query_params: HashMap<_, _> = callback_url.query_pairs().collect();

        match query_params.get("error") {
            Some(err) => return Err(format!("Failed authenticating user: {err}")),
            None => (),
        };

        let state = match query_params.get("state") {
            Some(state) => state.to_string(),
            None => return Err("No state found in callback".to_string()),
        };

        if state != self.state {
            return Err("Incorrect state found in callback".to_string());
        }

        let code = match query_params.get("code") {
            Some(code) => code,
            None => return Err("No code found in callback".to_string()),
        };

        let base_token_url =
            Url::from_str(DEFAULT_TOKEN_HOST).expect("Unable to init gcloud token url from base");

        let mut token_params: Vec<(&str, &str)> = DEFAULT_TOKEN_PARAMS.to_vec();
        token_params.push(("redirect_uri", redirect_uri));
        token_params.push(("code", code));

        let uri = append_query_params_to_url(base_token_url, token_params);

        Ok(uri.to_string())
    }

    /// Method that handles taking the token url returned by google from step 2
    /// and extracts the access_token
    ///
    /// https://developers.google.com/identity/protocols/oauth2/web-server#exchange-authorization-code
    pub fn handle_token_callback(
        &mut self,
        token_callback_uri: &str,
    ) -> Result<GCloudIdentity, String> {
        let callback_url = match Url::parse(token_callback_uri) {
            Ok(url) => url,
            Err(err) => return Err(format!("Failed parsing gcloud callback url: {err}")),
        };

        let query_params: HashMap<_, _> = callback_url.query_pairs().collect();

        match query_params.get("error") {
            Some(err) => return Err(format!("Failed exchanging code for token: {err}")),
            None => (),
        };

        let access_token = match query_params.get("access_token") {
            Some(access_token) => access_token.to_string(),
            None => return Err("No access_token found in callback".to_string()),
        };

        let refresh_token = match query_params.get("refresh_token") {
            Some(refresh_token) => refresh_token.to_string(),
            None => return Err("No refresh_token found in callback".to_string()),
        };

        let expires_in = match query_params.get("expires_in") {
            Some(expires_in) => expires_in.parse::<u64>().unwrap(), // might panic
            None => return Err("No expires_in found in callback".to_string()),
        };

        // no need to check token_type it's always set to "Bearer"

        let identity = GCloudIdentity::new(access_token, refresh_token, expires_in);
        Ok(identity)
    }
}

fn validate_redirect_uri(redirect_uri: &str) {
    if !redirect_uri.starts_with("http://localhost") {
        panic!("Redirect URI scheme must start with http://localhost");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const VALID_REDIRECT_URI: &str = "http://localhost:8080";

    #[test]
    fn should_generate_auth_uri() {
        let gca = GCloudAuth::default();
        assert_eq!(gca.get_login_uri(VALID_REDIRECT_URI), format!("https://accounts.google.com/o/oauth2/auth?response_type=code&access_type=offline&client_id=32555940559.apps.googleusercontent.com&redirect_uri=http%3A%2F%2Flocalhost%3A8080&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fappengine.admin+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fsqlservice.login+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcompute+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Faccounts.reauth&state={}", gca.state));
    }

    #[test]
    #[should_panic(expected = "Redirect URI scheme must start with http://localhost")]
    fn should_fail_to_generate_auth_uri_with_incorrect_redirect_uri() {
        let gca = GCloudAuth::default();
        gca.get_login_uri("http://not-localhost");
    }

    #[test]
    #[should_panic(expected = "Redirect URI scheme must start with http://localhost")]
    #[allow(unused_must_use)]
    fn should_fail_to_generate_token_uri_with_incorrect_redirect_uri() {
        let gca = GCloudAuth::default();
        gca.get_token_uri("not-important-right-now", "http://not-localhost");
    }

    #[test]
    fn should_fail_to_parse_callback_uri_if_uri_invalid() {
        let gca = GCloudAuth::default();
        assert_eq!(
            gca.get_token_uri("http:[...]", VALID_REDIRECT_URI),
            Err("Failed parsing gcloud callback url: invalid IPv6 address".to_string())
        );
    }

    #[test]
    fn should_fail_if_an_error_was_returned_by_google() {
        let gca = GCloudAuth::default();
        assert_eq!(
            gca.get_token_uri(
                "http:locahost:8080/?error=access_denied",
                VALID_REDIRECT_URI
            ),
            Err("Failed authenticating user: access_denied".to_string())
        );
    }

    #[test]
    fn should_fail_if_no_state_included_in_callback_uri() {
        let gca = GCloudAuth::default();
        assert_eq!(
            gca.get_token_uri("http:locahost:8080", VALID_REDIRECT_URI),
            Err("No state found in callback".to_string())
        );
    }

    #[test]
    fn should_fail_if_state_does_not_match() {
        let gca = GCloudAuth::default();
        assert_eq!(
            gca.get_token_uri("http:locahost:8080/?state=XXX", VALID_REDIRECT_URI),
            Err("Incorrect state found in callback".to_string())
        );
    }

    #[test]
    fn should_fail_if_no_code_included_in_callback_uri() {
        let gca = GCloudAuth::default();
        assert_eq!(
            gca.get_token_uri(
                format!("http:locahost:8080/?state={}", gca.state).as_str(),
                VALID_REDIRECT_URI
            ),
            Err("No code found in callback".to_string())
        );
    }

    #[test]
    fn should_generate_token_url_to_be_exchanged_for_token() {
        let gca = GCloudAuth::default();
        let callback_uri = format!("http:locahost:8080/?state={}&code=XXX", gca.state);
        assert_eq!(gca.get_token_uri(callback_uri.as_str(), VALID_REDIRECT_URI).unwrap(), "https://oauth2.googleapis.com/token?client_id=32555940559.apps.googleusercontent.com&client_secret=ZmssLNjJy2998hD4CTg2ejr2&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080&code=XXX");
    }
}
