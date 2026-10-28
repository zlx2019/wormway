//! The SQLite database: versions of the dynamic settings and small values of this instance.

use std::error::Error;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use zora_core::config::DynamicConfig;

use crate::token::random_hex;

/// Schema changes, embedded from `migrations/` at compile time.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// The database of one zora instance.
#[derive(Clone, Debug)]
pub struct Store {
    /// Connections to the database file.
    pool: SqlitePool,
}

/// Who made a configuration change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub enum ChangeSource {
    /// The Admin API.
    Api,
    /// The dashboard.
    Ui,
    /// The `zora` command line.
    Cli,
    /// The configuration file.
    File,
}

/// A saved version of the dynamic settings, without the settings themselves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct SavedVersion {
    /// Number of the version; newer versions have larger numbers.
    pub id: i64,
    /// When it was saved, as an RFC 3339 timestamp in UTC.
    pub created_at: String,
    /// Who made the change.
    pub source: ChangeSource,
    /// Note given with the change.
    pub comment: String,
}

/// A saved version with its content, as read from the table.
#[derive(sqlx::FromRow)]
struct VersionRow {
    /// The version.
    #[sqlx(flatten)]
    version: SavedVersion,
    /// The dynamic settings as JSON.
    content: String,
}

impl Store {
    /// Opens the database at `path`, creating it if needed, and brings its schema up to date.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            // WAL lets readers run while a change is written; NORMAL is durable enough with it.
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(|e| StoreError::new(format!("cannot open {}", path.display()), e))?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|e| StoreError::new("cannot update the database schema", e))?;
        Ok(Self { pool })
    }

    /// Closes every connection. Later calls fail.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Returns the ID of this instance, created on first use.
    pub async fn instance_id(&self) -> Result<String, StoreError> {
        let fresh = random_hex(16).map_err(|e| StoreError::new("cannot create an ID", e))?;
        let failed = |e| StoreError::new("cannot read the instance ID", e);
        sqlx::query("INSERT OR IGNORE INTO kv (key, value) VALUES ('instance_id', ?)")
            .bind(fresh)
            .execute(&self.pool)
            .await
            .map_err(failed)?;
        sqlx::query_scalar("SELECT value FROM kv WHERE key = 'instance_id'")
            .fetch_one(&self.pool)
            .await
            .map_err(failed)
    }

    /// Saves `config` as a new version.
    pub async fn save_version(
        &self,
        config: &DynamicConfig,
        source: ChangeSource,
        comment: &str,
    ) -> Result<SavedVersion, StoreError> {
        let content = serde_json::to_string(config)
            .map_err(|e| StoreError::new("cannot encode the configuration", e))?;
        sqlx::query_as(
            "INSERT INTO config_versions (source, comment, content) VALUES (?, ?, ?) \
             RETURNING id, created_at, source, comment",
        )
        .bind(source)
        .bind(comment)
        .bind(content)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StoreError::new("cannot save the configuration", e))
    }

    /// Returns the newest version, which is the configuration in effect, with its settings.
    pub async fn latest_version(
        &self,
    ) -> Result<Option<(SavedVersion, DynamicConfig)>, StoreError> {
        let row = sqlx::query_as(
            "SELECT id, created_at, source, comment, content FROM config_versions \
             ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::new("cannot read the latest configuration", e))?;
        row.map(decode).transpose()
    }

    /// Returns version `id` with its settings.
    pub async fn version(
        &self,
        id: i64,
    ) -> Result<Option<(SavedVersion, DynamicConfig)>, StoreError> {
        let row = sqlx::query_as(
            "SELECT id, created_at, source, comment, content FROM config_versions WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::new(format!("cannot read configuration version {id}"), e))?;
        row.map(decode).transpose()
    }

    /// Lists up to `limit` versions, newest first, starting below version `before` if given.
    pub async fn versions(
        &self,
        limit: u32,
        before: Option<i64>,
    ) -> Result<Vec<SavedVersion>, StoreError> {
        sqlx::query_as(
            "SELECT id, created_at, source, comment FROM config_versions WHERE id < ? \
             ORDER BY id DESC LIMIT ?",
        )
        .bind(before.unwrap_or(i64::MAX))
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::new("cannot list the configuration versions", e))
    }
}

/// Parses the settings stored with a version.
fn decode(row: VersionRow) -> Result<(SavedVersion, DynamicConfig), StoreError> {
    let config = serde_json::from_str(&row.content).map_err(|e| {
        StoreError::new(
            format!("configuration version {} is unreadable", row.version.id),
            e,
        )
    })?;
    Ok((row.version, config))
}

/// A database error, with what zora was doing when it happened.
#[derive(Debug, thiserror::Error)]
#[error("{action}")]
pub struct StoreError {
    /// What failed, such as "cannot save the configuration".
    action: String,
    /// The underlying error.
    #[source]
    source: Box<dyn Error + Send + Sync>,
}

impl StoreError {
    /// Wraps `source`, which happened during `action`.
    fn new(action: impl Into<String>, source: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self {
            action: action.into(),
            source: source.into(),
        }
    }
}
