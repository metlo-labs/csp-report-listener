mod auth;
mod pages;
mod report;
mod state;
mod token;
mod utils;

use log::{error, info};
use std::{env, net::SocketAddr, time::Duration};

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use dotenv::dotenv;
use lazy_static::lazy_static;
use report::{append_buffer_items, BufferItem};
use tokio::sync::RwLock;

const LOG_LEVELS: [&str; 5] = ["trace", "debug", "info", "warn", "error"];

lazy_static! {
    pub static ref REPORT_BUFFER: RwLock<Vec<BufferItem>> = RwLock::new(vec![]);
}

async fn health() -> &'static str {
    "OK"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenv().ok();

    let log_level = match env::var("METLO_LOG_LEVEL") {
        Ok(s) if LOG_LEVELS.contains(&s.as_str()) => s,
        _ => "info".to_owned(),
    };
    env::set_var("RUST_LOG", log_level);
    env_logger::init();

    let app_state = state::AppState::make_app_state().await?;

    let app_state_appender = app_state.clone();
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let mut buf_write = REPORT_BUFFER.write().await;
            let buffer_items: Vec<BufferItem> = buf_write.drain(..).collect();
            drop(buf_write);
            if let Err(e) = append_buffer_items(app_state_appender.clone(), buffer_items) {
                error!("Error appending buffer items: {}", e);
            };
        }
    });

    let auth_routes = Router::new()
        .route("/api/verify", get(health))
        .route("/api/reports", get(report::get_reports))
        .route("/api/tokens", get(token::get_tokens))
        .route("/api/token/:id", delete(token::delete_token))
        .route("/api/distinct-reports", get(report::get_distinct_reports))
        .route(
            "/api/violation-count",
            get(report::get_violation_count_by_day),
        )
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::auth_middleware,
        ));
    let no_auth_routes = Router::new()
        .route("/api", get(health))
        .route("/api/gen-token", post(auth::new_token))
        .route("/", post(report::report_csp))
        .route("/", get(pages::index));

    let app = Router::new()
        .merge(auth_routes)
        .merge(no_auth_routes)
        .with_state(app_state);

    let port: u16 = env::var("METLO_PORT")
        .unwrap_or("8080".to_string())
        .parse()
        .unwrap_or(8080);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("⚡️ Starting server at {}", addr.to_string());
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
