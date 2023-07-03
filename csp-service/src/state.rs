use std::{env, fs, path::Path};

use deadpool_sqlite::{Config, Pool as SQLitePool, Runtime};
use duckdb::DuckdbConnectionManager;
use r2d2;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: SQLitePool,
    pub duckdb_pool: r2d2::Pool<DuckdbConnectionManager>,
    pub secret_key: String,
}

const METLO_DATA_PATH_DEFAULT: &str = "/tmp/metlo_csp/";

impl AppState {
    pub async fn make_app_state() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let metlo_data_path =
            env::var("METLO_DATA_PATH").unwrap_or(METLO_DATA_PATH_DEFAULT.to_owned());
        fs::create_dir_all(&metlo_data_path)?;

        let path = Path::new(&metlo_data_path);
        let db_conn_string = path.join("metlo_csp.db").to_string_lossy().to_string();
        let duckdb_conn_string = path.join("metlo_csp.duckdb").to_string_lossy().to_string();
        let secret_key = env::var("METLO_SECRET_KEY")
            .map_err(|e| format!("Error getting METLO_SECRET_KEY: {}", e))?;

        let cfg = Config::new(db_conn_string);
        let db_pool = cfg.create_pool(Runtime::Tokio1).unwrap();
        db_pool.resize(2);

        let db_conn = db_pool.get().await?;
        db_conn
            .interact(|conn| {
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS api_token ( id INTEGER PRIMARY KEY, prefix TEXT NOT NULL, hash TEXT NOT NULL );",
                    (),
                )
            })
            .await
            .map_err(|e| format!("Error interacting with sqllilte: {}", e))?
            .map_err(|e| format!("Error running sqllilte query: {}", e))?;

        let manager = DuckdbConnectionManager::file(duckdb_conn_string)?;
        let duckdb_pool = r2d2::Pool::builder().max_size(4).build(manager).unwrap();

        let duck_conn = duckdb_pool.get()?;
        duck_conn.execute_batch(
            r"CREATE SEQUENCE IF NOT EXISTS csp_report_seq;
              CREATE TABLE IF NOT EXISTS csp_report (
                source_ip TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                document_uri TEXT NOT NULL,
                referrer TEXT NOT NULL,
                violated_directive TEXT NOT NULL,
                effective_directive TEXT NOT NULL,
                original_policy TEXT NOT NULL,
                disposition TEXT NOT NULL,
                blocked_uri TEXT,
                line_number UINTEGER,
                column_number UINTEGER,
                source_file TEXT,
                status_code UINTEGER,
                script_sample TEXT NOT NULL,
              );
             ",
        )?;

        Ok(AppState {
            db_pool,
            duckdb_pool,
            secret_key,
        })
    }
}
