use std::env;
use std::sync::Arc;

use dotenv::dotenv;
use oauth2::basic::{
    BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
    BasicTokenResponse, BasicTokenType,
};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, Client, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, StandardRevocableToken, TokenResponse, TokenUrl,
};
use rocket::response::Redirect;

#[macro_use]
extern crate rocket;

use rocket::http::{Cookie, CookieJar, SameSite, Status};
use rocket::serde::json::Json;
use rocket::time::Duration;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct Context {
    pub oauth_client: Arc<OauthClient>,
}

type OauthClient = Client<
    BasicErrorResponse,
    BasicTokenResponse,
    BasicTokenType,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
>;

type Ctx = rocket::State<Context>;

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    dotenv().ok(); // Start DotENV to read the .env file

    let oauth_client = BasicClient::new(
        ClientId::new(env::var("OAUTH_CLIENT_ID").expect("Invalid OAUTH_CLIENT_ID")),
        Some(ClientSecret::new(
            env::var("OAUTH_CLIENT_SECRET").expect("Invalid OAUTH_CLIENT_SECRET"),
        )),
        AuthUrl::new("https://unsplash.com/oauth/authorize".to_string()).unwrap(),
        Some(TokenUrl::new("https://unsplash.com/oauth/token".to_string()).unwrap()),
    )
    .set_redirect_uri(
        // RedirectUrl::new("http://localhost:8080/auth/callback".to_string()).unwrap(),
        RedirectUrl::new("https://cattinator.felixklg.dev/auth/callback".to_string()).unwrap(),
    );

    let _rocket = rocket::build()
        .mount("/", routes![index, auth, auth_callback])
        .manage(Context {
            oauth_client: Arc::new(oauth_client),
        })
        .launch()
        .await?;
    Ok(())
}

#[get("/")]
async fn index() -> Redirect {
    Redirect::to("https://github.com/felixklg/cattinator")
}

#[get("/auth")]
async fn auth(ctx: &Ctx, jar: &CookieJar<'_>) -> Redirect {
    let (auth_url, csrf_token) = ctx // Define auth_url and csrf_token
        .oauth_client // Fetch Client from state
        .authorize_url(CsrfToken::new_random) // CSRF token for preventing CSRF attacks
        .add_scope(Scope::new("public".to_string())) // OAuth Scopes
        .url(); // Build the URL

    let cookie = Cookie::build("csrf_token", csrf_token.secret().to_string())
        .http_only(true)
        .secure(true)
        .max_age(Duration::minutes(10))
        .same_site(SameSite::Lax);

    jar.add_private(cookie.finish());

    Redirect::to(auth_url.to_string()) // Redirect to the auth_url
}

#[derive(Responder)]
enum AuthError {
    #[response(status = 400)]
    MissingCode(Status),
    #[response(status = 403)]
    MissingState(Status),
    #[response(status = 403)]
    CsrfError(Status),
    #[response(status = 500)]
    ServerError(Status),
}

#[derive(Serialize, Deserialize)]
struct AuthResponse {
    access_token: String,
    refresh_token: String,
    scope: String,
}

#[get("/auth/callback?<code>&<state>&<error>&<error_description>")]
async fn auth_callback(
    jar: &CookieJar<'_>,
    ctx: &Ctx,
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
) -> Result<Json<AuthResponse>, AuthError> {
    if let Some(_) = error {
        return Err(AuthError::MissingCode(Status::BadRequest));
    }
    if let Some(_) = error_description {
        return Err(AuthError::MissingCode(Status::BadRequest));
    }

    match jar.get_private("csrf_token") {
        Some(csrf_cookie) => {
            if let Some(state) = state {
                if state != csrf_cookie.value() {
                    return Err(AuthError::CsrfError(Status::Forbidden));
                }
            }
        }
        None => return Err(AuthError::MissingState(Status::Forbidden)),
    }
    jar.remove_private(Cookie::named("csrf_token"));

    if let Some(code) = code {
        let token_result = ctx
            .oauth_client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await;
        if let Err(_) = token_result {
            return Err(AuthError::ServerError(Status::InternalServerError));
        }

        let tokens = token_result.unwrap();

        return Ok(Json(AuthResponse {
            access_token: tokens.access_token().secret().to_string(),
            refresh_token: tokens.refresh_token().unwrap().secret().to_string(),
            scope: "public".to_string(),
        }));
    } else {
        return Err(AuthError::MissingCode(Status::BadRequest));
    }
}