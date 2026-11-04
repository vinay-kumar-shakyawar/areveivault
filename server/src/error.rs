use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

/// Uniform API error: `{ "error": <code>, "message": <text> }` (+ extra fields for 409).
#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub extra: Option<Value>,
}

pub type ApiResult<T> = Result<T, AppError>;

impl AppError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        AppError { status, code, message: message.into(), extra: None }
    }
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", m)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "authentication required")
    }
    pub fn invalid_credentials() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "invalid credentials")
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", m)
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "not found")
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", m)
    }
    pub fn conflict_with(current: Value) -> Self {
        let mut e = Self::conflict("item was modified by someone else");
        e.extra = Some(json!({ "current": current }));
        e
    }
    pub fn rate_limited() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many attempts, try again later")
    }
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.code, "message": self.message });
        if let Some(Value::Object(extra)) = self.extra {
            for (k, v) in extra {
                body[k] = v;
            }
        }
        (self.status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &e {
            match db.code().as_deref() {
                Some("23505") => return AppError::conflict("already exists"),
                Some("23503") => return AppError::bad_request("references an unknown object"),
                Some("23514") => return AppError::bad_request("invalid value"),
                _ => {}
            }
        }
        tracing::error!(error = %e, "database error");
        AppError::internal()
    }
}

impl From<redis::RedisError> for AppError {
    fn from(e: redis::RedisError) -> Self {
        tracing::error!(error = %e, "redis error");
        AppError::internal()
    }
}

impl From<arevei_core::Error> for AppError {
    fn from(e: arevei_core::Error) -> Self {
        AppError::bad_request(e.to_string())
    }
}

impl From<JsonRejection> for AppError {
    fn from(e: JsonRejection) -> Self {
        AppError::bad_request(e.body_text())
    }
}

impl From<PathRejection> for AppError {
    fn from(e: PathRejection) -> Self {
        AppError::bad_request(e.body_text())
    }
}

impl From<QueryRejection> for AppError {
    fn from(e: QueryRejection) -> Self {
        AppError::bad_request(e.body_text())
    }
}
