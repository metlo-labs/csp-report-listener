use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use deadpool_sqlite::rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{state::AppState, utils::internal_error};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Token {
    id: i64,
    prefix: String,
}

pub async fn get_tokens(
    State(state): State<AppState>,
) -> Result<Json<Vec<Token>>, (StatusCode, String)> {
    let db_conn = state.db_pool.get().await.map_err(internal_error)?;
    db_conn
        .interact(move |conn| {
            let mut stmt = conn
                .prepare("SELECT id, prefix FROM api_token")
                .map_err(internal_error)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(Token {
                        id: row.get(0)?,
                        prefix: row.get(1)?,
                    })
                })
                .map_err(internal_error)?;
            let tokens = rows
                .collect::<Result<Vec<Token>, _>>()
                .map_err(internal_error)?;
            Ok(Json(tokens))
        })
        .await
        .map_err(internal_error)?
}

pub async fn delete_token(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<Vec<Token>>, (StatusCode, String)> {
    let db_conn = state.db_pool.get().await.map_err(internal_error)?;

    db_conn
        .interact(move |conn| {
            conn.execute("DELETE FROM api_token WHERE id = ?", params![id])
                .map_err(internal_error)
        })
        .await
        .map_err(internal_error)??;
    db_conn
        .interact(move |conn| {
            let mut stmt = conn
                .prepare("SELECT id, prefix FROM api_token")
                .map_err(internal_error)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(Token {
                        id: row.get(0)?,
                        prefix: row.get(1)?,
                    })
                })
                .map_err(internal_error)?;
            let tokens = rows
                .collect::<Result<Vec<Token>, _>>()
                .map_err(internal_error)?;
            Ok(Json(tokens))
        })
        .await
        .map_err(internal_error)?
}
