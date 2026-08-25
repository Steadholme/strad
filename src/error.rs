use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{message}")]
    Api {
        status: StatusCode,
        code: &'static str,
        message: &'static str,
        retryable: bool,
    },
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("filesystem operation failed")]
    Io(#[from] std::io::Error),
    #[error("upstream operation failed")]
    Upstream,
    #[error("server invariant violated: {0}")]
    Invariant(&'static str),
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
    request_id: String,
    retryable: bool,
}

impl AppError {
    pub fn api(
        status: StatusCode,
        code: &'static str,
        message: &'static str,
        retryable: bool,
    ) -> Self {
        Self::Api {
            status,
            code,
            message,
            retryable,
        }
    }

    pub fn invalid(code: &'static str, message: &'static str) -> Self {
        Self::api(StatusCode::BAD_REQUEST, code, message, false)
    }

    pub fn not_found() -> Self {
        Self::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "The requested resource was not found.",
            false,
        )
    }

    pub fn conflict(code: &'static str, message: &'static str) -> Self {
        Self::api(StatusCode::CONFLICT, code, message, false)
    }

    pub fn unavailable(code: &'static str, message: &'static str) -> Self {
        Self::api(StatusCode::SERVICE_UNAVAILABLE, code, message, true)
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Api { code, .. } => code,
            Self::Database(_) => "database_unavailable",
            Self::Io(_) => "storage_unavailable",
            Self::Upstream => "upstream_unavailable",
            Self::Invariant(_) => "server_invariant_violation",
        }
    }

    pub fn retryable(&self) -> bool {
        match self {
            Self::Api { retryable, .. } => *retryable,
            Self::Database(_) | Self::Io(_) | Self::Upstream => true,
            Self::Invariant(_) => false,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message, retryable) = match &self {
            Self::Api {
                status,
                code,
                message,
                retryable,
            } => (*status, *code, *message, *retryable),
            Self::Database(error) => {
                tracing::error!(error = %error, "database operation failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "database_unavailable",
                    "The workbench database is temporarily unavailable.",
                    true,
                )
            }
            Self::Io(error) => {
                tracing::error!(error = %error, "filesystem operation failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    "Workbench storage is temporarily unavailable.",
                    true,
                )
            }
            Self::Upstream => (
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream_unavailable",
                "A required upstream service is unavailable.",
                true,
            ),
            Self::Invariant(detail) => {
                tracing::error!(detail, "server invariant violation");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_invariant_violation",
                    "The operation could not be completed safely.",
                    false,
                )
            }
        };
        let mut response = (
            status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    code,
                    message,
                    request_id: Uuid::new_v4().to_string(),
                    retryable,
                },
            }),
        )
            .into_response();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        }
        response
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
