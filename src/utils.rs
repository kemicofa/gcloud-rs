use url::Url;

pub fn append_query_params_to_url(mut url: Url, params: Vec<(&str, &str)>) -> Url {
    {
        let mut query_pairs = url.query_pairs_mut();
        for (key, value) in params {
            query_pairs.append_pair(key, value);
        }
    }
    url
}
