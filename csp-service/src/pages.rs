use axum::response::Html;

const INDEX_PAGE: &str = include_str!("./html/index.html");

pub async fn index() -> Html<&'static str> {
    Html(INDEX_PAGE)
}
