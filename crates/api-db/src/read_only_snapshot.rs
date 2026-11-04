/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! Pooled read-only snapshots whose cancellation releases local connection
//! capacity even when PostgreSQL is still executing a blocked statement.

/// `ReadOnlySnapshotSession` owns a pooled connection until successful work explicitly
/// returns it through `return_to_pool`. Dropping the guard before that discards
/// the connection and immediately releases the local pool slot.
///
/// SQLx's normal cleanup can wait for a blocked query before rollback, so the
/// guard also covers setup and network stalls that the statement cap cannot.
pub struct ReadOnlySnapshotSession {
    connection: Option<sqlx::pool::PoolConnection<sqlx::Postgres>>,
}

impl ReadOnlySnapshotSession {
    /// Wraps the pooled connection before `BEGIN`, so failed or cancelled
    /// transaction startup still releases its pool slot.
    pub async fn acquire(pool: &sqlx::PgPool) -> Result<Self, crate::DatabaseError> {
        Ok(Self {
            connection: Some(
                pool.acquire()
                    .await
                    .map_err(crate::DatabaseError::acquire)?,
            ),
        })
    }

    /// Starts a consistent, read-only snapshot with a transaction-local server
    /// limit of at most `timeout` per subsequent statement. A shorter
    /// operator setting remains in effect. The separate client deadline covers
    /// acquisition and setup; the server limit does not cover those stages.
    /// The cap is truncated to milliseconds, with a minimum of one millisecond
    /// so a submillisecond duration cannot disable PostgreSQL's timeout.
    pub async fn begin(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<crate::Transaction<'_>, crate::DatabaseError> {
        let connection = self
            .connection
            .as_deref_mut()
            .expect("the snapshot retains its connection until return_to_pool consumes it");
        let mut txn = crate::Transaction::begin_inner(connection).await?;
        crate::set_read_only_snapshot(txn.as_pgconn()).await?;

        // `pg_settings` reports milliseconds. `NULLIF` turns a disabled (zero)
        // timeout into NULL, which `LEAST` ignores when applying our cap. A
        // shorter limit remains unchanged. The `true` argument makes this
        // transaction-local, so the setting resets when the txn ends.
        sqlx::query(
            "SELECT set_config('statement_timeout', \
                LEAST(NULLIF(setting::bigint, 0), $1::text::bigint)::text, true) \
             FROM pg_settings WHERE name = 'statement_timeout'",
        )
        .bind(timeout.as_millis().max(1).to_string())
        .execute(txn.as_pgconn())
        .await
        .map_err(|error| {
            crate::DatabaseError::query("set read-only snapshot statement timeout", error)
        })?;
        Ok(txn)
    }

    /// Returns a healthy connection through SQLx after its transaction commits.
    pub fn return_to_pool(mut self) {
        drop(self.connection.take());
    }
}

impl Drop for ReadOnlySnapshotSession {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            // Detaching frees the local pool slot immediately. Closing the
            // socket does not guarantee that PostgreSQL stops immediately;
            // after snapshot setup, its statement timeout separately bounds
            // each subsequent SQL statement. Discarded server sessions may
            // briefly remain alongside replacements and exceed the pool limit.
            drop(connection.detach());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Snapshot setup must configure read-only, repeatable-read queries and the
    /// server cap without extending a tighter operator limit or changing the
    /// setting used by later pool borrowers.
    #[crate::sqlx_test]
    async fn snapshot_statement_timeout_is_capped_and_transaction_local(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = ReadOnlySnapshotSession::acquire(&pool).await?;
        for (configured_ms, cap, expected_ms) in [
            // A disabled server timeout still needs the snapshot's limit.
            (0, std::time::Duration::from_secs(5), 5000_i64),
            // A broader site limit must not extend snapshot SQL work.
            (60000, std::time::Duration::from_secs(5), 5000),
            // Preserve an operator's stricter limit.
            (1000, std::time::Duration::from_secs(5), 1000),
            // The shared helper must use its caller's budget, rather than
            // retaining the original power-details constant internally.
            (0, std::time::Duration::from_millis(1500), 1500),
        ] {
            sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                .bind(configured_ms.to_string())
                .execute(
                    connection
                        .connection
                        .as_deref_mut()
                        .expect("snapshot lease"),
                )
                .await?;

            let mut txn = connection.begin(cap).await?;
            let effective_ms: i64 = sqlx::query_scalar(
                "SELECT setting::bigint FROM pg_settings WHERE name = 'statement_timeout'",
            )
            .fetch_one(txn.as_pgconn())
            .await?;
            assert_eq!(effective_ms, expected_ms, "configured {configured_ms}ms");
            let (read_only, isolation): (String, String) = sqlx::query_as(
                "SELECT current_setting('transaction_read_only'), \
                        current_setting('transaction_isolation')",
            )
            .fetch_one(txn.as_pgconn())
            .await?;
            assert_eq!(read_only, "on");
            assert_eq!(isolation, "repeatable read");
            txn.commit().await?;

            let restored_ms: i64 = sqlx::query_scalar(
                "SELECT setting::bigint FROM pg_settings WHERE name = 'statement_timeout'",
            )
            .fetch_one(
                connection
                    .connection
                    .as_deref_mut()
                    .expect("snapshot lease"),
            )
            .await?;
            assert_eq!(restored_ms, configured_ms, "configured {configured_ms}ms");
        }
        connection.return_to_pool();

        Ok(())
    }
}
