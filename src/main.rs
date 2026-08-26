use std::{net::SocketAddr, time::Duration};

use strad::{app::AppState, config::Config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("healthcheck") => return http_check("/healthz").await,
        Some("readycheck") => return http_check("/readyz").await,
        Some("runtime-contract") => return runtime_contract(),
        _ => {}
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "strad=info,tower_http=info".into()),
        )
        .init();
    let config = Config::from_env().map_err(|error| format!("configuration error: {error}"))?;
    strad::migrations::run(&config.database_url)
        .await
        .map_err(|error| format!("migration error: {error}"))?;
    let bind_addr = config.bind_addr;
    let state = AppState::build(config)
        .await
        .map_err(|error| format!("startup error: {error}"))?;
    let _workers = strad::workers::spawn(state.clone());
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(address = %bind_addr, "Strad listening");
    axum::serve(listener, strad::app::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn http_check(path: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    let configured = std::env::var("STRAD_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:9360".into());
    let bind_addr: SocketAddr = configured
        .parse()
        .map_err(|_| "STRAD_BIND_ADDR must be a socket address")?;
    let target = SocketAddr::from(([127, 0, 0, 1], bind_addr.port()));
    tokio::time::timeout(Duration::from_secs(5), async move {
        let mut stream = tokio::net::TcpStream::connect(target).await?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut response = [0u8; 128];
        let count = stream.read(&mut response).await?;
        if count == 0
            || !(response[..count].starts_with(b"HTTP/1.1 200 ")
                || response[..count].starts_with(b"HTTP/1.0 200 "))
        {
            return Err(std::io::Error::other(
                "health endpoint did not return HTTP 200",
            ));
        }
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| "healthcheck timed out")??;
    Ok(())
}

fn runtime_contract() -> Result<(), Box<dyn std::error::Error>> {
    let model = std::env::var("STRAD_NEWAPI_MODEL")
        .map_err(|_| "STRAD_NEWAPI_MODEL is required for runtime-contract")?;
    if !strad::config::valid_model_alias(&model) {
        return Err("STRAD_NEWAPI_MODEL is invalid".into());
    }
    let context_tokens: u32 = std::env::var("STRAD_NEWAPI_CONTEXT_TOKENS")
        .map_err(|_| "STRAD_NEWAPI_CONTEXT_TOKENS is required for runtime-contract")?
        .parse()
        .map_err(|_| "STRAD_NEWAPI_CONTEXT_TOKENS must be an integer")?;
    if context_tokens < 32_768 {
        return Err("STRAD_NEWAPI_CONTEXT_TOKENS must be at least 32768".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "newapi_model": model,
            "newapi_context_tokens": context_tokens,
        })
    );
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %error, "failed to install Ctrl-C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(error = %error, "failed to install SIGTERM handler"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
