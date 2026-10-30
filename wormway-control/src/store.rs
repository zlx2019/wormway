//! The SQLite database: versions of the dynamic settings, small values of this instance, and
//! the accounts and certificates of ACME. It holds private keys, so only its owner may read it.

use std::error::Error;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use wormway_core::config::DynamicConfig;

use crate::token::random_hex;

/// Schema changes, embedded from `migrations/` at compile time.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// The database of one Wormway instance.
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
    /// The `wormway` command line.
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

/// A certificate issued through ACME, as saved: what it was ordered for, and its chain and key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeCertificateRecord {
    /// The ACME directory that issued it.
    pub directory: String,
    /// The host names it was ordered for, sorted.
    pub domains: Vec<String>,
    /// The certificate chain, leaf first, as PEM.
    pub chain: String,
    /// The private key, as PEM.
    pub key: String,
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
    /// The file, and those SQLite keeps next to it, become readable by their owner only.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        #[cfg(unix)]
        restrict(path).map_err(|e| {
            StoreError::new(format!("cannot restrict access to {}", path.display()), e)
        })?;
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

    /// Returns the credentials of the ACME account at `directory`, if one was saved.
    pub async fn acme_account(&self, directory: &str) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar("SELECT credentials FROM acme_accounts WHERE directory = ?")
            .bind(directory)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::new("cannot read the ACME account", e))
    }

    /// Saves the credentials of the ACME account at `directory`, in place of any before.
    pub async fn save_acme_account(
        &self,
        directory: &str,
        credentials: &str,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT OR REPLACE INTO acme_accounts (directory, credentials) VALUES (?, ?)")
            .bind(directory)
            .bind(credentials)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|e| StoreError::new("cannot save the ACME account", e))
    }

    /// Returns the certificate issued through ACME for certificate `name`, if one was saved.
    pub async fn acme_certificate(
        &self,
        name: &str,
    ) -> Result<Option<AcmeCertificateRecord>, StoreError> {
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            "SELECT directory, domains, chain, key FROM acme_certificates WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::new("cannot read the ACME certificate", e))?;
        let Some((directory, domains, chain, key)) = row else {
            return Ok(None);
        };
        let domains = serde_json::from_str(&domains)
            .map_err(|e| StoreError::new(format!("ACME certificate {name} is unreadable"), e))?;
        Ok(Some(AcmeCertificateRecord {
            directory,
            domains,
            chain,
            key,
        }))
    }

    /// Saves `certificate` as the one issued through ACME for certificate `name`, in place of
    /// any before.
    pub async fn save_acme_certificate(
        &self,
        name: &str,
        certificate: &AcmeCertificateRecord,
    ) -> Result<(), StoreError> {
        let domains = serde_json::to_string(&certificate.domains)
            .map_err(|e| StoreError::new("cannot encode the host names", e))?;
        sqlx::query(
            "INSERT OR REPLACE INTO acme_certificates (name, directory, domains, chain, key) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(name)
        .bind(&certificate.directory)
        .bind(domains)
        .bind(&certificate.chain)
        .bind(&certificate.key)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| StoreError::new("cannot save the ACME certificate", e))
    }

    /// Removes the certificate issued through ACME for certificate `name`, if there is one.
    pub async fn remove_acme_certificate(&self, name: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM acme_certificates WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|e| StoreError::new("cannot remove the ACME certificate", e))
    }

    /// Returns the names of the certificates issued through ACME that were saved, in order.
    pub async fn acme_certificate_names(&self) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar("SELECT name FROM acme_certificates ORDER BY name")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::new("cannot list the ACME certificates", e))
    }
}

/// Creates the database file at `path` if needed, and makes it and the files SQLite keeps
/// next to it readable and writable by their owner only; files that SQLite creates later take
/// the permissions of the database file.
#[cfg(unix)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    let companions = ["-wal", "-shm"].map(|suffix| {
        let mut companion = path.as_os_str().to_owned();
        companion.push(suffix);
        std::path::PathBuf::from(companion)
    });
    for file in std::iter::once(path.to_owned()).chain(companions) {
        match std::fs::set_permissions(&file, Permissions::from_mode(0o600)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    Ok(())
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

/// A database error, with what Wormway was doing when it happened.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A certificate as ACME would leave it.
    fn record(domains: &[&str]) -> AcmeCertificateRecord {
        AcmeCertificateRecord {
            directory: "https://ca.test/dir".to_owned(),
            domains: domains.iter().map(|domain| (*domain).to_owned()).collect(),
            chain: "the certificate chain".to_owned(),
            key: "the private key".to_owned(),
        }
    }

    /// Accounts are kept by directory and certificates by name; saving again replaces them,
    /// the names of the certificates come back in order, and a removed certificate is gone.
    #[tokio::test]
    async fn keeps_acme_accounts_and_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("wormway.db")).await.unwrap();
        let directory = "https://ca.test/dir";
        assert_eq!(store.acme_account(directory).await.unwrap(), None);
        store
            .save_acme_account(directory, "{\"a\":1}")
            .await
            .unwrap();
        store
            .save_acme_account(directory, "{\"a\":2}")
            .await
            .unwrap();
        let account = store.acme_account(directory).await.unwrap();
        assert_eq!(account.as_deref(), Some("{\"a\":2}"));
        let other = store.acme_account("https://other.test/dir").await.unwrap();
        assert_eq!(other, None);

        assert_eq!(store.acme_certificate("site").await.unwrap(), None);
        let first = record(&["a.test"]);
        store.save_acme_certificate("site", &first).await.unwrap();
        let next = record(&["a.test", "b.test"]);
        store.save_acme_certificate("site", &next).await.unwrap();
        assert_eq!(store.acme_certificate("site").await.unwrap(), Some(next));
        store.save_acme_certificate("api", &first).await.unwrap();
        let names = store.acme_certificate_names().await.unwrap();
        assert_eq!(names, ["api", "site"]);
        store.remove_acme_certificate("site").await.unwrap();
        assert_eq!(store.acme_certificate("site").await.unwrap(), None);
        store.remove_acme_certificate("site").await.unwrap();
        assert_eq!(store.acme_certificate_names().await.unwrap(), ["api"]);
    }

    /// The database holds private keys: a new file is readable by its owner only, and an
    /// existing one is restricted when it is opened, with the files SQLite keeps next to it.
    #[cfg(unix)]
    #[tokio::test]
    async fn restricts_the_database_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let mode = |file: &str| {
            let metadata = std::fs::metadata(dir.path().join(file)).unwrap();
            metadata.permissions().mode() & 0o777
        };
        let path = dir.path().join("wormway.db");
        let store = Store::open(&path).await.unwrap();
        store.instance_id().await.unwrap();
        assert_eq!(mode("wormway.db"), 0o600);
        assert_eq!(mode("wormway.db-wal"), 0o600);
        store.close().await;

        let open = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&path, open.clone()).unwrap();
        std::fs::write(dir.path().join("wormway.db-shm"), b"").unwrap();
        std::fs::set_permissions(dir.path().join("wormway.db-shm"), open).unwrap();
        let store = Store::open(&path).await.unwrap();
        assert_eq!(mode("wormway.db"), 0o600);
        assert_eq!(mode("wormway.db-shm"), 0o600);
        store.close().await;
    }
}
