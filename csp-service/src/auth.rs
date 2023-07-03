use axum::{
    extract::State,
    http::{self, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::{engine::general_purpose, Engine as _};
use deadpool_sqlite::rusqlite::OptionalExtension;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha512;

use crate::{state::AppState, utils::internal_error};

type HmacSha512 = Hmac<Sha512>;

pub async fn auth_middleware<B>(
    State(state): State<AppState>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, (StatusCode, String)> {
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());
    let auth_header = if let Some(auth_header) = auth_header {
        auth_header
    } else {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()));
    };

    let mut mac =
        HmacSha512::new_from_slice(state.secret_key.as_bytes()).map_err(internal_error)?;
    mac.update(auth_header.as_bytes());
    let hash_bytes = mac.finalize().into_bytes();
    let api_key_hash = general_purpose::STANDARD.encode(hash_bytes);

    let db_conn = state.db_pool.get().await.map_err(internal_error)?;
    let res = db_conn
        .interact(|conn| {
            conn.query_row(
                "SELECT id FROM api_token WHERE hash = ?",
                [api_key_hash],
                |e| {
                    let val: i64 = e.get(0)?;
                    Ok(val)
                },
            )
            .optional()
        })
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;

    match res {
        None => Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string())),
        _ => Ok(next.run(req).await),
    }
}

pub async fn new_token<B>(
    State(state): State<AppState>,
    req: Request<B>,
) -> Result<String, (StatusCode, String)> {
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());
    match auth_header {
        Some(e) if e.trim() == state.secret_key => (),
        _ => return Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string())),
    }
    let random_bytes = rand::thread_rng().gen::<[u8; 30]>();
    let b64_str = general_purpose::STANDARD.encode(random_bytes);
    let prefix = b64_str[..5].to_owned();

    let mut mac =
        HmacSha512::new_from_slice(state.secret_key.as_bytes()).map_err(internal_error)?;
    mac.update(b64_str.as_bytes());
    let hash_bytes = mac.finalize().into_bytes();
    let api_key_hash = general_purpose::STANDARD.encode(hash_bytes);

    let db_conn = state.db_pool.get().await.map_err(internal_error)?;
    db_conn
        .interact(|conn| {
            conn.execute(
                "INSERT INTO api_token (prefix, hash) VALUES (?, ?)",
                [prefix, api_key_hash],
            )
            .optional()
        })
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;

    Ok(b64_str)
}
