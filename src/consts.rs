/// These credentials are taken from the mirror google-cloud-sdk and they should
/// eventually be replaced by our own. For testing purposes this is ok.
///
/// https://github.com/google-cloud-sdk-unofficial/google-cloud-sdk/blob/4ec4e98c5038a92221c3a1013d91167c0dd0ae9f/lib/googlecloudsdk/core/config.py#L168

pub const CLOUDSDK_CLIENT_ID: &str = "32555940559.apps.googleusercontent.com";
pub const CLOUDSDK_CLIENT_NOTSOSECRET: &str = "ZmssLNjJy2998hD4CTg2ejr2";

/// These scopes are taken from the mirror google-cloud-sdk
pub const CLOUDSDK_EXTERNAL_ACCOUNT_SCOPES: [&str; 6] = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/appengine.admin",
    "https://www.googleapis.com/auth/sqlservice.login",
    "https://www.googleapis.com/auth/compute",
    "https://www.googleapis.com/auth/accounts.reauth", // required if 2fa
];

pub const DEFAULT_AUTH_HOST: &str = "https://accounts.google.com/o/oauth2/auth";
pub const DEFAULT_TOKEN_HOST: &str = "https://oauth2.googleapis.com/token";

pub const DEFAULT_AUTH_PARAMS: [(&str, &str); 3] = [
    ("response_type", "code"),
    ("access_type", "offline"),
    ("client_id", CLOUDSDK_CLIENT_ID),
];

pub const DEFAULT_TOKEN_PARAMS: [(&str, &str); 3] = [
    ("client_id", CLOUDSDK_CLIENT_ID),
    ("client_secret", CLOUDSDK_CLIENT_NOTSOSECRET),
    ("grant_type", "authorization_code"),
];

pub const DEFAULT_REFRESH_PARAMS: [(&str, &str); 3] = [
    ("client_id", CLOUDSDK_CLIENT_ID),
    ("client_secret", CLOUDSDK_CLIENT_NOTSOSECRET),
    ("grant_type", "refresh_token"),
];
