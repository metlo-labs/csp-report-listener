use axum::{
    extract::{self, State},
    http::StatusCode,
    Json,
};
use duckdb::{params_from_iter, ToSql};
use log::error;
use serde::{Deserialize, Serialize};

use crate::{state::AppState, utils::internal_error, REPORT_BUFFER};

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct CspReport {
    pub document_uri: String,
    pub referrer: String,
    pub violated_directive: String,
    pub effective_directive: String,
    pub original_policy: String,
    pub disposition: String,
    pub blocked_uri: Option<String>,
    pub line_number: Option<u32>,
    pub column_number: Option<u32>,
    pub source_file: Option<String>,
    pub status_code: Option<u32>,
    pub script_sample: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BufferItem {
    pub document_uri: String,
    pub created_at: String,
    pub referrer: String,
    pub violated_directive: String,
    pub effective_directive: String,
    pub original_policy: String,
    pub disposition: String,
    pub blocked_uri: Option<String>,
    pub line_number: Option<u32>,
    pub column_number: Option<u32>,
    pub source_file: Option<String>,
    pub status_code: Option<u32>,
    pub script_sample: String,
    pub source_ip: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DistinctReport {
    pub violated_directive: String,
    pub effective_directive: String,
    pub original_policy: String,
    pub disposition: String,
    pub blocked_uri: Option<String>,
    pub source_file: Option<String>,
    pub script_sample: String,
    pub first_seen: String,
    pub cnt: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ViolationCount {
    pub day: String,
    pub base_uri: u64,
    pub script_src: u64,
    pub img_src: u64,
    pub style_src: u64,
    pub connect_src: u64,
    pub media_src: u64,
    pub object_src: u64,
    pub frame_src: u64,
    pub font_src: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct ReportPayload {
    pub csp_report: CspReport,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetReportQueryParams {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDistinctReportQueryParams {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub async fn report_csp(
    extract::Json(payload): extract::Json<ReportPayload>,
) -> Result<&'static str, (StatusCode, String)> {
    let source_ip = "".to_owned();
    let report = payload.csp_report;
    if let Ok(ref mut buf_write) = REPORT_BUFFER.try_write() {
        buf_write.push(BufferItem {
            document_uri: report.document_uri,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            referrer: report.referrer,
            violated_directive: report.violated_directive,
            effective_directive: report.effective_directive,
            original_policy: report.original_policy,
            disposition: report.disposition,
            blocked_uri: report.blocked_uri,
            line_number: report.line_number,
            column_number: report.column_number,
            source_file: report.source_file,
            status_code: report.status_code,
            script_sample: report.script_sample,
            source_ip,
        });
    }
    Ok("OK")
}

pub async fn get_violation_count_by_day(
    State(state): State<AppState>,
) -> Result<Json<Vec<ViolationCount>>, (StatusCode, String)> {
    let conn = state.duckdb_pool.get().map_err(internal_error)?;

    let query = "
        SELECT
            CAST(CAST(created_at AS DATE) AS TEXT) AS day,
            COUNT(CASE WHEN violated_directive ILIKE 'base-uri%' THEN 1 END) AS base_uri,
            COUNT(CASE WHEN violated_directive ILIKE 'script-src%' THEN 1 END) AS script_src,
            COUNT(CASE WHEN violated_directive ILIKE 'img-src%' THEN 1 END) AS img_src,
            COUNT(CASE WHEN violated_directive ILIKE 'style-src%' THEN 1 END) AS style_src,
            COUNT(CASE WHEN violated_directive ILIKE 'connect-src%' THEN 1 END) AS connect_src,
            COUNT(CASE WHEN violated_directive ILIKE 'media-src%' THEN 1 END) AS media_src,
            COUNT(CASE WHEN violated_directive ILIKE 'object-src%' THEN 1 END) AS object_src,
            COUNT(CASE WHEN violated_directive ILIKE 'frame-src%' THEN 1 END) AS frame_src,
            COUNT(CASE WHEN violated_directive ILIKE 'font-src%' THEN 1 END) AS font_src,
        FROM csp_report
        GROUP BY 1
        ORDER BY 1 ASC
        LIMIT 14
    ";

    let mut stmt = conn.prepare(query).map_err(internal_error)?;

    let res: Vec<ViolationCount> = stmt
        .query_map([], |e| {
            Ok(ViolationCount {
                day: e.get(0)?,
                base_uri: e.get(1)?,
                script_src: e.get(2)?,
                img_src: e.get(3)?,
                style_src: e.get(4)?,
                connect_src: e.get(5)?,
                media_src: e.get(6)?,
                object_src: e.get(7)?,
                frame_src: e.get(8)?,
                font_src: e.get(9)?,
            })
        })
        .map_err(internal_error)?
        .collect::<Result<Vec<ViolationCount>, duckdb::Error>>()
        .map_err(internal_error)?;

    Ok(Json(res))
}

pub async fn get_reports(
    State(state): State<AppState>,
    extract::Query(query_params): extract::Query<GetReportQueryParams>,
) -> Result<Json<Vec<BufferItem>>, (StatusCode, String)> {
    let conn = state.duckdb_pool.get().map_err(internal_error)?;

    let mut query = "
        SELECT
            document_uri,
            CAST(created_at AS STRING),
            referrer,
            violated_directive,
            effective_directive,
            original_policy,
            disposition,
            blocked_uri,
            line_number,
            column_number,
            source_file,
            status_code,
            script_sample,
            source_ip
        FROM csp_report
    "
    .to_string();
    let mut params: Vec<&dyn ToSql> = vec![];

    if query_params.limit.is_some() {
        params.push(&query_params.limit);
        query.push_str(" LIMIT ?")
    }
    if query_params.offset.is_some() {
        params.push(&query_params.offset);
        query.push_str(" OFFSET ?")
    }

    let mut stmt = conn.prepare(query.as_str()).map_err(internal_error)?;
    let reports: Vec<BufferItem> = stmt
        .query_map(params_from_iter(params), |e| {
            Ok(BufferItem {
                document_uri: e.get(0)?,
                created_at: e.get(1)?,
                referrer: e.get(2)?,
                violated_directive: e.get(3)?,
                effective_directive: e.get(4)?,
                original_policy: e.get(5)?,
                disposition: e.get(6)?,
                blocked_uri: e.get(7)?,
                line_number: e.get(8)?,
                column_number: e.get(9)?,
                source_file: e.get(10)?,
                status_code: e.get(11)?,
                script_sample: e.get(12)?,
                source_ip: e.get(13)?,
            })
        })
        .map_err(internal_error)?
        .collect::<Result<Vec<BufferItem>, duckdb::Error>>()
        .map_err(internal_error)?;

    Ok(Json(reports))
}

pub async fn get_distinct_reports(
    State(state): State<AppState>,
    extract::Query(query_params): extract::Query<GetDistinctReportQueryParams>,
) -> Result<Json<Vec<DistinctReport>>, (StatusCode, String)> {
    let conn = state.duckdb_pool.get().map_err(internal_error)?;

    let mut query = "
        SELECT
            violated_directive,
            effective_directive,
            original_policy,
            disposition,
            blocked_uri,
            source_file,
            script_sample,
            CAST(MIN(created_at) AS STRING) as first_seen,
            COUNT(*) as cnt
        FROM csp_report
        GROUP BY 1, 2, 3, 4, 5, 6, 7
        ORDER BY 8 DESC
    "
    .to_string();
    let mut params: Vec<&dyn ToSql> = vec![];

    if query_params.limit.is_some() {
        params.push(&query_params.limit);
        query.push_str(" LIMIT ?")
    }
    if query_params.offset.is_some() {
        params.push(&query_params.offset);
        query.push_str(" OFFSET ?")
    }

    let mut stmt = conn.prepare(query.as_str()).map_err(internal_error)?;
    let reports: Vec<DistinctReport> = stmt
        .query_map(params_from_iter(params), |e| {
            Ok(DistinctReport {
                violated_directive: e.get(0)?,
                effective_directive: e.get(1)?,
                original_policy: e.get(2)?,
                disposition: e.get(3)?,
                blocked_uri: e.get(4)?,
                source_file: e.get(5)?,
                script_sample: e.get(6)?,
                first_seen: e.get(7)?,
                cnt: e.get(8)?,
            })
        })
        .map_err(internal_error)?
        .collect::<Result<Vec<DistinctReport>, duckdb::Error>>()
        .map_err(internal_error)?;

    Ok(Json(reports))
}

pub fn append_buffer_items(
    state: AppState,
    buffer_items: Vec<BufferItem>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = state.duckdb_pool.get()?;
    let mut app = conn.appender("csp_report")?;

    let mut rows: Vec<[&dyn ToSql; 14]> = vec![];

    for i in 0..buffer_items.len() {
        rows.push([
            &buffer_items[i].source_ip as &dyn ToSql,
            &buffer_items[i].created_at as &dyn ToSql,
            &buffer_items[i].document_uri as &dyn ToSql,
            &buffer_items[i].referrer as &dyn ToSql,
            &buffer_items[i].violated_directive as &dyn ToSql,
            &buffer_items[i].effective_directive as &dyn ToSql,
            &buffer_items[i].original_policy as &dyn ToSql,
            &buffer_items[i].disposition as &dyn ToSql,
            &buffer_items[i].blocked_uri as &dyn ToSql,
            &buffer_items[i].line_number as &dyn ToSql,
            &buffer_items[i].column_number as &dyn ToSql,
            &buffer_items[i].source_file as &dyn ToSql,
            &buffer_items[i].status_code as &dyn ToSql,
            &buffer_items[i].script_sample as &dyn ToSql,
        ]);
    }
    if let Err(e) = app.append_rows(rows) {
        error!("Error appending rows: {}", e);
    }

    Ok(())
}
