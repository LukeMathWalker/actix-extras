use super::SessionKey;
use crate::storage::interface::{LoadError, SaveError, SessionState, UpdateError};
use crate::storage::SessionStore;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::convert::TryInto;
use std::sync::Arc;
use time::{self, Duration};

/// Use Redis as session storage backend.
///
/// ```no_run
/// use actix_web::{web, App, HttpServer, HttpResponse, Error};
/// use actix_session::{SessionMiddleware, storage::RedisSessionStore};
/// use actix_web::cookie::Key;
///
/// // The secret key would usually be read from a configuration file/environment variables.
/// fn get_secret_key() -> Key {
///     # todo!()
///     // [...]
/// }
///
/// #[actix_rt::main]
/// async fn main() -> std::io::Result<()> {
///     let secret_key = get_secret_key();
///     let redis_connection_string = "redis://127.0.0.1:6379";
///     let store = RedisSessionStore::new(redis_connection_string).await.unwrap();
///     HttpServer::new(move ||
///             App::new()
///             .wrap(SessionMiddleware::new(
///                 store.clone(),
///                 secret_key.clone()
///             ))
///             .default_service(web::to(|| HttpResponse::Ok())))
///         .bind(("127.0.0.1", 8080))?
///         .run()
///         .await
/// }
/// ```
///
/// ## Implementation notes
///
/// `RedisSessionStore` leverages [`redis-rs`](https://github.com/mitsuhiko/redis-rs) as Redis client.
#[derive(Clone)]
pub struct RedisSessionStore {
    configuration: CacheConfiguration,
    client: ConnectionManager,
}

#[derive(Clone)]
struct CacheConfiguration {
    cache_keygen: Arc<dyn Fn(&str) -> String + Send + Sync>,
}

impl Default for CacheConfiguration {
    fn default() -> Self {
        Self {
            cache_keygen: Arc::new(|s| s.to_owned()),
        }
    }
}

impl RedisSessionStore {
    /// A fluent API to configure [`RedisSessionStore`].
    /// It takes as input the only required input to create a new instance of [`RedisSessionStore`] - a
    /// connection string for Redis.
    #[must_use]
    pub fn builder<S: Into<String>>(connection_string: S) -> RedisSessionStoreBuilder {
        RedisSessionStoreBuilder {
            configuration: Default::default(),
            connection_string: connection_string.into(),
        }
    }

    /// Create a new instance of [`RedisSessionStore`] using the default configuration.
    /// It takes as input the only required input to create a new instance of [`RedisSessionStore`] - a
    /// connection string for Redis.
    pub async fn new<S: Into<String>>(
        connection_string: S,
    ) -> Result<RedisSessionStore, anyhow::Error> {
        Self::builder(connection_string).build().await
    }
}

/// A fluent builder to construct a [`RedisActorSessionStore`] instance with custom
/// configuration parameters.
#[must_use]
pub struct RedisSessionStoreBuilder {
    connection_string: String,
    configuration: CacheConfiguration,
}

impl RedisSessionStoreBuilder {
    /// Set a custom cache key generation strategy, expecting a session key as input.
    #[must_use]
    pub fn cache_keygen(mut self, keygen: Arc<dyn Fn(&str) -> String + Send + Sync>) -> Self {
        self.configuration.cache_keygen = keygen;
        self
    }

    /// Finalise the builder and return a [`RedisActorSessionStore`] instance.
    pub async fn build(self) -> Result<RedisSessionStore, anyhow::Error> {
        let client = ConnectionManager::new(redis::Client::open(self.connection_string)?).await?;
        Ok(RedisSessionStore {
            configuration: self.configuration,
            client,
        })
    }
}

#[async_trait::async_trait(?Send)]
impl SessionStore for RedisSessionStore {
    async fn load(&self, session_key: &SessionKey) -> Result<Option<SessionState>, LoadError> {
        let cache_key = (self.configuration.cache_keygen)(session_key.as_ref());
        let value: Option<String> = self
            .client
            .clone()
            .get(cache_key)
            .await
            .map_err(Into::into)
            .map_err(LoadError::GenericError)?;
        match value {
            None => Ok(None),
            Some(value) => Ok(serde_json::from_str(&value)
                .map_err(Into::into)
                .map_err(LoadError::DeserializationError)?),
        }
    }

    async fn save(
        &self,
        session_state: SessionState,
        ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        let body = serde_json::to_string(&session_state)
            .map_err(Into::into)
            .map_err(SaveError::SerializationError)?;
        let session_key: SessionKey = generate_session_key()
            .try_into()
            .map_err(Into::into)
            .map_err(SaveError::GenericError)?;
        let cache_key = (self.configuration.cache_keygen)(session_key.as_ref());
        redis::cmd("SET")
            .arg(&[
                &cache_key,
                &body,
                "NX",
                "EX",
                &format!("{}", ttl.whole_seconds()),
            ])
            .query_async(&mut self.client.clone())
            .await
            .map_err(Into::into)
            .map_err(SaveError::GenericError)?;
        Ok(session_key)
    }

    async fn update(
        &self,
        session_key: SessionKey,
        session_state: SessionState,
        ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        let body = serde_json::to_string(&session_state)
            .map_err(Into::into)
            .map_err(UpdateError::SerializationError)?;
        let cache_key = (self.configuration.cache_keygen)(session_key.as_ref());
        redis::cmd("SET")
            .arg(&[
                &cache_key,
                &body,
                "XX",
                "EX",
                &format!("{}", ttl.whole_seconds()),
            ])
            .query_async(&mut self.client.clone())
            .await
            .map_err(Into::into)
            .map_err(UpdateError::GenericError)?;
        Ok(session_key)
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        let cache_key = (self.configuration.cache_keygen)(session_key.as_ref());
        self.client
            .clone()
            .del(&cache_key)
            .await
            .map_err(Into::into)
            .map_err(UpdateError::GenericError)?;
        Ok(())
    }
}

/// This session key generation routine follows [OWASP's recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy).
fn generate_session_key() -> String {
    let value = std::iter::repeat(())
        .map(|()| OsRng.sample(Alphanumeric))
        .take(64)
        .collect::<Vec<_>>();
    String::from_utf8(value).unwrap()
}

#[cfg(test)]
mod test {
    use crate::storage::redis_rs::RedisSessionStore;
    use crate::test_helpers::acceptance_test_suite;

    #[actix_rt::test]
    // GitHub Actions do not support service containers (i.e. Redis, in our case) on
    // non-Linux runners, therefore this test will fail in CI due to connection issues on those platform
    #[cfg_attr(any(target_os = "macos", target_os = "windows"), ignore)]
    async fn test_session_workflow() {
        let redis_store = RedisSessionStore::new("redis://127.0.0.1:6379")
            .await
            .unwrap();
        acceptance_test_suite(move || redis_store.clone(), true).await;
    }
}
