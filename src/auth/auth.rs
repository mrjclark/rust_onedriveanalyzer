use oauth2::{
    AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl,
    AuthorizationCode, CsrfToken, Scope, basic::BasicClient
};

// Initialize the OAuth2 client for Microsoft identity platform
pub fn create_oauth_client() -> BasicClient {
    BasicClient::new(
        ClientId::new("your_client_id".to_string()),
        Some(ClientSecret::new("your_client_secret".to_string())),
        AuthUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string()).expect("Invalid authorization endpoint URL"),
        Some(TokenUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string()).expect("Invalid token endpoint URL"))
    )
    .set_redirect_uri(RedirectUrl::new("http://localhost:8080/callback".to_string()).expect("Invalid redirect URL"))
}

pub async fn authenticate(code: String) -> Result<String, Box<dyn std::error::Error>> {
    let client = create_oauth_client();

    // 1) Build auth URL and open it in browser
    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("offline_access openid profile Files.Read.All".to_string()))
        .url();
    // open auth_url in browser and complete consent

    // 2) After redirect, get the `code` query param and exchange it for a token
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .request(oauth2::reqwest::http_client)?;
    Ok(token_response.access_token().secret().to_string())
}
