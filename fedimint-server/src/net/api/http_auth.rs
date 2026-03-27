use std::error::Error as StdError;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::bail;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use fedimint_logging::LOG_NET_AUTH;
use futures::{Future, FutureExt as _, TryFutureExt as _};
use http::HeaderValue;
use hyper::body::Body;
use hyper::{Request, Response, http};
use subtle::ConstantTimeEq as _;
use tower::Service;
use tracing::{debug, info};

#[derive(Clone, Debug)]
pub struct HttpAuthLayer {
    // surprisingly, a new `HttpAuthService` is created on every http request, so to avoid
    // cloning every element of the vector, we pre-compute and `Arc` the whole thing
    auth_base64: Arc<Vec<String>>,
    bcrypt_hash: Option<Arc<bcrypt::HashParts>>,
}

impl HttpAuthLayer {
    pub fn new(secrets: &[String], bcrypt_hash: Option<Arc<bcrypt::HashParts>>) -> Self {
        if secrets.is_empty() && bcrypt_hash.is_none() {
            info!(target: LOG_NET_AUTH, "Api available for public access");
        } else {
            info!(
                target: LOG_NET_AUTH,
                num_secrets = secrets.len(),
                has_bcrypt = bcrypt_hash.is_some(),
                "Api available for private access"
            );
        }
        Self {
            auth_base64: secrets
                .iter()
                .map(|p| STANDARD.encode(format!("fedimint:{p}")))
                .collect::<Vec<_>>()
                .into(),
            bcrypt_hash,
        }
    }
}

impl<S> tower::Layer<S> for HttpAuthLayer {
    type Service = HttpAuthService<S>;

    fn layer(&self, service: S) -> Self::Service {
        HttpAuthService {
            inner: service,
            auth_base64: self.auth_base64.clone(),
            bcrypt_hash: self.bcrypt_hash.clone(),
        }
    }
}

#[derive(Clone)]
pub struct HttpAuthService<S> {
    inner: S,
    auth_base64: Arc<Vec<String>>,
    bcrypt_hash: Option<Arc<bcrypt::HashParts>>,
}

impl<S> HttpAuthService<S> {
    fn needs_auth(&self) -> bool {
        !self.auth_base64.is_empty() || self.bcrypt_hash.is_some()
    }

    fn check_auth(&self, base64_auth: &str) -> bool {
        self.auth_base64
            .iter()
            .any(|p| p.as_bytes().ct_eq(base64_auth.as_bytes()).into())
    }

    fn extract_password(auth_header: &HeaderValue) -> anyhow::Result<String> {
        let mut split = auth_header.to_str()?.split_ascii_whitespace();
        let method = split
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty auth header"))?;
        if method != "Basic" {
            bail!("Wrong auth method for bcrypt: expected Basic");
        }
        let encoded = split
            .next()
            .ok_or_else(|| anyhow::anyhow!("no auth string"))?;
        let decoded = STANDARD.decode(encoded)?;
        let decoded_str = std::str::from_utf8(&decoded)?;
        decoded_str
            .strip_prefix("fedimint:")
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("auth does not start with 'fedimint:'"))
    }

    fn check_bcrypt_auth(&self, auth_header: &HeaderValue) -> bool {
        let Some(hash) = &self.bcrypt_hash else {
            return false;
        };
        let Ok(password) = Self::extract_password(auth_header) else {
            return false;
        };
        bcrypt::verify(&password, &hash.to_string()).unwrap_or(false)
    }

    fn check_auth_header_value(&self, auth_header: &HeaderValue) -> anyhow::Result<bool> {
        let mut split = auth_header.to_str()?.split_ascii_whitespace();

        let Some(auth_method) = split.next() else {
            bail!("Invalid Request: empty value");
        };

        if auth_method != "Basic" {
            bail!("Invalid Request: Wrong auth method");
        }
        let Some(auth) = split.next() else {
            bail!("Invalid Request: no auth string");
        };

        if split.next().is_some() {
            bail!("Invalid Request: too many things");
        }

        // Check API secrets (force_api_secrets) via constant-time comparison
        if self.check_auth(auth) {
            return Ok(true);
        }

        // Check bcrypt guardian hash if configured
        Ok(self.bcrypt_hash.is_some() && self.check_bcrypt_auth(auth_header))
    }
}

impl<S, B: Body + 'static> Service<Request<B>> for HttpAuthService<S>
where
    S: Service<Request<B>, Response = jsonrpsee::core::http_helpers::Response>,
    S::Response: 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>> + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = Box<dyn StdError + Send + Sync + 'static>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let needs_auth = self.needs_auth();

        if !needs_auth {
            return Box::pin(self.inner.call(req).map_err(Into::into));
        }

        if let Some(auth_header) = req.headers().get(hyper::http::header::AUTHORIZATION) {
            let auth_ok = self.check_auth_header_value(auth_header).unwrap_or(false);

            if auth_ok {
                return Box::pin(self.inner.call(req).map_err(Into::into));
            }
        }

        debug!(target: LOG_NET_AUTH, "Access denied to incoming api connection");
        let mut response = Response::new(jsonrpsee::core::http_helpers::Body::new(
            "Unauthorized".to_string(),
        ));
        *response.status_mut() = http::StatusCode::UNAUTHORIZED;
        response.headers_mut().insert(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"Authentication needed\""),
        );
        async { Ok(response) }.boxed()
    }
}
