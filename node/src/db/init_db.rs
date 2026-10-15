use sqlx::{sqlite::SqliteConnectOptions, Executor, SqlitePool};
use std::{fs, path::Path, str::FromStr};

use crate::error::DBErrors;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};
static SCHEMA_SQL: &str = include_str!("schema.sql");
static AUDIT_SCHEMA_SQL: &str = include_str!("audit_schema.sql");

/// On-disk format version, stored in SQLite's `PRAGMA user_version`.
///
/// Version 2 is the protocol 2.0.0 bead format: 32-byte BIP340 x-only keys and 64-byte Schnorr
/// signatures. Databases created before versioning report 0 and hold 33-byte ECDSA-era keys
/// and DER signatures, which this node cannot decode.
pub const DB_FORMAT_VERSION: i64 = 2;

/// Initializes the braid database inside the node's data directory.
pub async fn init_db(datadir: &Path) -> Result<SqlitePool, DBErrors> {
    setup_sqlite_db(datadir, "braidpool.db", SCHEMA_SQL, "Bead").await
}

/// Initializes the audit database inside the node's data directory.
pub async fn init_audit_db(datadir: &Path) -> Result<SqlitePool, DBErrors> {
    setup_sqlite_db(datadir, "audit.db", AUDIT_SCHEMA_SQL, "AuditBead").await
}

async fn setup_sqlite_db(
    db_dir: &Path,
    db_name: &str,
    schema_sql: &str,
    bead_table: &str,
) -> Result<SqlitePool, DBErrors> {
    let db_path = db_dir.join(db_name);
    let dir_exists = db_dir.exists();

    // Create db directory if it doesn't exist
    if let Err(error) = fs::create_dir_all(db_dir) {
        return Err(DBErrors::DBDirectoryNotCreated {
            error: error.to_string(),
            path: db_path,
        });
    } else if !dir_exists {
        info!(path = %db_dir.display(), "DB directory created successfully");
    }

    let db_exists = db_path.exists();
    let db_url = format!("sqlite://{}", db_path.to_string_lossy());
    // SQl connection configurations
    let db_config = match SqliteConnectOptions::from_str(&db_url) {
        Ok(config) => config,
        Err(error) => {
            return Err(DBErrors::ConnectionUrlNotParsed {
                error: error.to_string(),
                url: db_url.to_string(),
            });
        }
    };
    let sql_lite_connections = db_config
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

    let pool = if db_exists {
        info!(db_path = %db_path.display(), "Using existing database");
        let pool = SqlitePool::connect_with(sql_lite_connections)
            .await
            .map_err(|error| DBErrors::ConnectionToSQlitePoolFailed {
                error: error.to_string(),
            })?;
        check_db_format(&pool, &db_path, bead_table).await?;
        pool
    } else {
        info!(db_path = %db_path.display(), "Creating new database");
        if let Err(e) = std::fs::File::create_new(&db_path) {
            error!(
                db_path = %db_path.display(),
                error = %e,
                "Failed to create database file"
            );
            return Err(DBErrors::DBDirectoryNotCreated {
                error: e.to_string(),
                path: db_path.clone(),
            });
        }

        let pool = SqlitePool::connect_with(sql_lite_connections)
            .await
            .map_err(|error| DBErrors::ConnectionToSQlitePoolFailed {
                error: error.to_string(),
            })?;

        pool.execute(schema_sql)
            .await
            .map_err(|error| DBErrors::SchemaNotInitialized {
                error: error.to_string(),
                db_path: db_path.clone(),
            })?;
        set_db_format_version(&pool, &db_path).await?;
        info!(db_path = %db_path.display(), "Database schema initialized");

        // Force WAL checkpoint to flush schema changes to disk
        match sqlx::query("PRAGMA wal_checkpoint(FULL)")
            .execute(&pool)
            .await
        {
            Ok(_) => {
                info!("WAL checkpoint completed successfully");
            }
            Err(error) => {
                warn!(error = ?error, "WAL checkpoint failed");
            }
        }
        pool
    };

    Ok(pool)
}

async fn set_db_format_version(pool: &SqlitePool, db_path: &Path) -> Result<(), DBErrors> {
    // PRAGMA does not accept bound parameters; the value is a constant.
    pool.execute(format!("PRAGMA user_version = {DB_FORMAT_VERSION}").as_str())
        .await
        .map(|_| ())
        .map_err(|error| DBErrors::SchemaNotInitialized {
            error: error.to_string(),
            db_path: db_path.to_path_buf(),
        })
}

/// Refuse to open a database written by another format version.
///
/// A database from before versioning (`user_version` 0) that holds no beads is simply stamped
/// with the current version; one that holds beads cannot be read and the operator is told what
/// to do, instead of failing later with a decode error on the first row.
async fn check_db_format(
    pool: &SqlitePool,
    db_path: &Path,
    bead_table: &str,
) -> Result<(), DBErrors> {
    let incompatible = |found_version: i64, detail: &str| DBErrors::IncompatibleDatabase {
        db_path: db_path.to_path_buf(),
        found_version,
        expected_version: DB_FORMAT_VERSION,
        detail: detail.to_string(),
    };
    let found_version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(pool)
        .await
        .map_err(|error| DBErrors::TupleNotFetched {
            error: error.to_string(),
        })?;
    if found_version == DB_FORMAT_VERSION {
        return Ok(());
    }
    if found_version > DB_FORMAT_VERSION {
        return Err(incompatible(
            found_version,
            "it was written by a newer version of the node; upgrade the node",
        ));
    }
    let table_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(bead_table)
            .fetch_one(pool)
            .await
            .map_err(|error| DBErrors::TupleNotFetched {
                error: error.to_string(),
            })?;
    if table_exists > 0 {
        // The table name is one of two internal constants, never user input.
        let has_beads: i64 = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {bead_table} LIMIT 1)"
        ))
        .fetch_one(pool)
        .await
        .map_err(|error| DBErrors::TupleNotFetched {
            error: error.to_string(),
        })?;
        if has_beads != 0 {
            return Err(incompatible(
                found_version,
                "it holds beads from before protocol 2.0.0 (33-byte ECDSA keys and DER \
                 signatures), which cannot be read. Stop the node and delete this file (and its \
                 -wal and -shm files) to start from an empty braid",
            ));
        }
    }
    set_db_format_version(pool, db_path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "braidpool-initdb-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn user_version(pool: &SqlitePool) -> i64 {
        sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Insert one bead row with a 33-byte key and a DER-length signature, as old nodes wrote.
    async fn insert_legacy_bead(pool: &SqlitePool, table: &str) {
        let sql = if table == "Bead" {
            "INSERT INTO Bead (hash, hashPrevBlock, hashMerkleRoot, payout_address, \
             start_timestamp, comm_pub_key, miner_ip, extranonce1, extranonce2, \
             broadcast_timestamp, signature) \
             VALUES (x'01', x'02', x'03', x'04', 1, zeroblob(33), 'ip', 'a', 'b', 2, zeroblob(70))"
        } else {
            return;
        };
        pool.execute(sql).await.unwrap();
    }

    #[tokio::test]
    async fn new_database_is_stamped_with_the_current_version() {
        let dir = unique_dir();
        let pool = init_db(&dir).await.unwrap();
        assert_eq!(user_version(&pool).await, DB_FORMAT_VERSION);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn current_version_database_reopens() {
        let dir = unique_dir();
        init_db(&dir).await.unwrap().close().await;
        let pool = init_db(&dir).await.unwrap();
        assert_eq!(user_version(&pool).await, DB_FORMAT_VERSION);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn legacy_database_with_beads_is_refused_with_instructions() {
        let dir = unique_dir();
        let pool = init_db(&dir).await.unwrap();
        insert_legacy_bead(&pool, "Bead").await;
        pool.execute("PRAGMA user_version = 0").await.unwrap(); // as an unversioned database
        pool.close().await;
        let err = init_db(&dir).await.unwrap_err();
        match &err {
            DBErrors::IncompatibleDatabase {
                found_version,
                expected_version,
                detail,
                ..
            } => {
                assert_eq!(*found_version, 0);
                assert_eq!(*expected_version, DB_FORMAT_VERSION);
                assert!(detail.contains("delete"), "{detail}");
            }
            other => panic!("expected IncompatibleDatabase, got {other:?}"),
        }
        assert!(err.to_string().contains("version 0"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn legacy_database_without_beads_is_upgraded_in_place() {
        let dir = unique_dir();
        let pool = init_db(&dir).await.unwrap();
        pool.execute("PRAGMA user_version = 0").await.unwrap();
        pool.close().await;
        let pool = init_db(&dir).await.unwrap();
        assert_eq!(user_version(&pool).await, DB_FORMAT_VERSION);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn newer_database_is_refused() {
        let dir = unique_dir();
        let pool = init_db(&dir).await.unwrap();
        pool.execute("PRAGMA user_version = 99").await.unwrap();
        pool.close().await;
        let err = init_db(&dir).await.unwrap_err();
        assert!(matches!(
            err,
            DBErrors::IncompatibleDatabase {
                found_version: 99,
                ..
            }
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn audit_database_is_versioned_too() {
        let dir = unique_dir();
        let pool = init_audit_db(&dir).await.unwrap();
        assert_eq!(user_version(&pool).await, DB_FORMAT_VERSION);
        let _ = fs::remove_dir_all(&dir);
    }
}
