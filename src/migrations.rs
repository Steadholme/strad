use sha2::{Digest, Sha256};
use sqlx::{Connection, Executor, PgConnection, Row};

use crate::config::CURRENT_SCHEMA_VERSION;

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "strad_core",
        sql: include_str!("../migrations/0001_strad_core.sql"),
    },
    Migration {
        version: 2,
        name: "turn_model_alias",
        sql: include_str!("../migrations/0002_turn_model_alias.sql"),
    },
];

pub async fn run(database_url: &str) -> std::result::Result<(), String> {
    let mut connection = PgConnection::connect(database_url)
        .await
        .map_err(safe_db_error)?;
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('strad:migrations',0))")
        .execute(&mut connection)
        .await
        .map_err(safe_db_error)?;
    let result = run_locked(&mut connection).await;
    let unlock = sqlx::query("SELECT pg_advisory_unlock(hashtextextended('strad:migrations',0))")
        .execute(&mut connection)
        .await
        .map_err(safe_db_error);
    match (result, unlock) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(_)) => Ok(()),
    }
}

async fn run_locked(connection: &mut PgConnection) -> std::result::Result<(), String> {
    let mut bootstrap = connection.begin().await.map_err(safe_db_error)?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS strad_schema_migrations(\
         version bigint PRIMARY KEY,\
         name text NOT NULL,\
         sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),\
         applied_at timestamptz NOT NULL)",
    )
    .execute(&mut *bootstrap)
    .await
    .map_err(safe_db_error)?;
    exact_introspect(&mut bootstrap).await?;
    bootstrap.commit().await.map_err(safe_db_error)?;

    let rows =
        sqlx::query("SELECT version,name,sha256 FROM strad_schema_migrations ORDER BY version")
            .fetch_all(&mut *connection)
            .await
            .map_err(safe_db_error)?;
    let current = rows
        .last()
        .map(|row| row.get::<i64, _>("version"))
        .unwrap_or(0);
    if current != 0 && !(CURRENT_SCHEMA_VERSION - 1..=CURRENT_SCHEMA_VERSION).contains(&current) {
        return Err(format!(
            "database schema version {current} is incompatible with application schema {CURRENT_SCHEMA_VERSION}"
        ));
    }
    for (index, row) in rows.into_iter().enumerate() {
        let version: i64 = row.get("version");
        let name: String = row.get("name");
        let sha: String = row.get("sha256");
        if version != index as i64 + 1 {
            return Err("migration ledger is not a contiguous prefix".to_string());
        }
        let expected = MIGRATIONS
            .iter()
            .find(|migration| migration.version == version)
            .ok_or_else(|| format!("unknown applied migration version {version}"))?;
        if name != expected.name || sha != sha256(expected.sql.as_bytes()) {
            return Err(format!("migration drift detected at version {version}"));
        }
    }

    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version > current)
    {
        let mut tx = connection.begin().await.map_err(safe_db_error)?;
        tx.execute(migration.sql).await.map_err(safe_db_error)?;
        sqlx::query(
            "INSERT INTO strad_schema_migrations(version,name,sha256,applied_at) \
             VALUES($1,$2,$3,now())",
        )
        .bind(migration.version)
        .bind(migration.name)
        .bind(sha256(migration.sql.as_bytes()))
        .execute(&mut *tx)
        .await
        .map_err(safe_db_error)?;
        tx.commit().await.map_err(safe_db_error)?;
    }
    Ok(())
}

async fn exact_introspect(connection: &mut PgConnection) -> std::result::Result<(), String> {
    let columns = sqlx::query(
        "SELECT column_name,data_type,is_nullable,character_maximum_length \
         FROM information_schema.columns \
         WHERE table_schema=current_schema() AND table_name='strad_schema_migrations' \
         ORDER BY ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(safe_db_error)?;
    let actual: Vec<(String, String, String, Option<i32>)> = columns
        .iter()
        .map(|row| {
            (
                row.get("column_name"),
                row.get("data_type"),
                row.get("is_nullable"),
                row.try_get::<Option<i32>, _>("character_maximum_length")
                    .unwrap_or(None),
            )
        })
        .collect();
    let expected = vec![
        ("version".into(), "bigint".into(), "NO".into(), None),
        ("name".into(), "text".into(), "NO".into(), None),
        ("sha256".into(), "character".into(), "NO".into(), Some(64)),
        (
            "applied_at".into(),
            "timestamp with time zone".into(),
            "NO".into(),
            None,
        ),
    ];
    if actual != expected {
        return Err("strad_schema_migrations column drift detected".to_string());
    }
    // Exactly one primary-key constraint on version and one SHA format check are mandatory.
    // Extra constraints indicate a non-canonical bootstrap ledger and fail closed.
    let constraints: Vec<(String, String)> = sqlx::query(
        "SELECT c.contype::text AS kind, pg_get_constraintdef(c.oid) AS definition \
         FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid \
         JOIN pg_namespace n ON n.oid=t.relnamespace \
         WHERE n.nspname=current_schema() AND t.relname='strad_schema_migrations' \
         ORDER BY c.contype, c.conname",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(safe_db_error)?
    .into_iter()
    .map(|row| (row.get("kind"), row.get("definition")))
    .collect();
    let primary = constraints
        .iter()
        .filter(|(kind, definition)| kind == "p" && definition == "PRIMARY KEY (version)")
        .count();
    let sha_check = constraints
        .iter()
        .filter(|(kind, definition)| {
            kind == "c" && definition.contains("sha256") && definition.contains("[0-9a-f]{64}")
        })
        .count();
    let mut not_null: Vec<&str> = constraints
        .iter()
        .filter(|(kind, _)| kind == "n")
        .map(|(_, definition)| definition.as_str())
        .collect();
    not_null.sort_unstable();
    let expected_not_null = vec![
        "NOT NULL applied_at",
        "NOT NULL name",
        "NOT NULL sha256",
        "NOT NULL version",
    ];
    if constraints.len() != 6 || primary != 1 || sha_check != 1 || not_null != expected_not_null {
        return Err("strad_schema_migrations constraint drift detected".to_string());
    }
    Ok(())
}

pub async fn schema_compatible(pool: &sqlx::PgPool) -> bool {
    let rows =
        sqlx::query("SELECT version,name,sha256 FROM strad_schema_migrations ORDER BY version")
            .fetch_all(pool)
            .await;
    let Ok(rows) = rows else {
        return false;
    };
    let version = rows.len() as i64;
    if version != CURRENT_SCHEMA_VERSION && version != CURRENT_SCHEMA_VERSION - 1 {
        return false;
    }
    rows.iter().enumerate().all(|(index, row)| {
        let expected = &MIGRATIONS[index];
        row.get::<i64, _>("version") == index as i64 + 1
            && row.get::<String, _>("name") == expected.name
            && row.get::<String, _>("sha256") == sha256(expected.sql.as_bytes())
    })
}

pub fn migration_manifest_sha256() -> String {
    let mut digest = Sha256::new();
    for migration in MIGRATIONS {
        digest.update(migration.version.to_be_bytes());
        digest.update((migration.name.len() as u64).to_be_bytes());
        digest.update(migration.name.as_bytes());
        digest.update((migration.sql.len() as u64).to_be_bytes());
        digest.update(migration.sql.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn safe_db_error(error: sqlx::Error) -> String {
    tracing::error!(error = %error, "migration database operation failed");
    "migration database operation failed".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_is_checksum_bound_and_contains_frozen_tenant_constraints() {
        assert_eq!(migration_manifest_sha256().len(), 64);
        let sql = MIGRATIONS[0].sql;
        assert!(sql.contains("DEFERRABLE INITIALLY DEFERRED"));
        assert!(sql.contains("FOREIGN KEY (upload_id, id, owner_sub)"));
        assert!(sql.contains("source_outbox_id uuid UNIQUE"));
        assert!(sql.contains("retained_from_seq bigint NOT NULL"));
        assert!(sql.contains("frozen_request jsonb"));
    }

    #[test]
    fn turn_model_migration_is_additive_and_bounded() {
        let sql = MIGRATIONS[1].sql;
        assert_eq!(MIGRATIONS[1].version, CURRENT_SCHEMA_VERSION);
        assert!(sql.contains("ALTER TABLE turns ADD COLUMN model_alias text"));
        assert!(sql.contains("ALTER COLUMN model_alias SET NOT NULL"));
        assert!(sql.contains("turns_model_alias_valid"));
        assert!(sql.contains("openai/gpt-5.6-luna"));
    }
}
