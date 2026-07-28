use crate::PushPostgresError;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::fmt;

const RUNTIME_ROLES: &[&str] = &[
    "dtx_identity_runtime",
    "dtx_group_runtime",
    "dtx_mailbox_runtime",
    "dtx_push_identity_auth_runtime",
    "dtx_push_registration_runtime",
    "dtx_push_broker_runtime",
    "dtx_realtime_sync_runtime",
    "dtx_public_feed_runtime",
];
const PUSH_TABLES: &[&str] = &[
    "messaging.opaque_push_registrations",
    "messaging.opaque_push_idempotency_claims",
    "messaging.opaque_push_deliveries",
];
const PUSH_FUNCTIONS: &[&str] = &[
    "messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid)",
    "messaging.opaque_push_commit_put(uuid,bytea,uuid,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea,bytea,bytea,bytea,text,bytea)",
    "messaging.opaque_push_commit_delete(uuid,bytea,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea)",
    "messaging.claim_opaque_push_deliveries(uuid,integer)",
    "messaging.prune_opaque_push_terminal(integer)",
    "messaging.authorize_opaque_push_send(uuid,uuid)",
    "messaging.finish_opaque_push_accepted(uuid,uuid)",
    "messaging.finish_opaque_push_permanent_failure(uuid,uuid,text)",
    "messaging.finish_opaque_push_transient(uuid,uuid,integer,text)",
    "messaging.finish_opaque_push_invalid_token(uuid,uuid,bigint)",
];

fn validation_query(
    expected_role: &'static str,
    approved_functions: &[&'static str],
    identity_reader: bool,
) -> String {
    let mut function_checks = String::new();
    if identity_reader {
        // Identity auth must not have messaging schema USAGE; avoid
        // has_function_privilege on inaccessible qualified functions.
        function_checks
            .push_str(" AND NOT has_schema_privilege(current_user, 'messaging', 'USAGE')");
    } else {
        for function in approved_functions {
            function_checks.push_str(" AND has_function_privilege(current_user, '");
            function_checks.push_str(function);
            function_checks.push_str("', 'EXECUTE')");
        }
        for function in PUSH_FUNCTIONS {
            if !approved_functions.contains(function) {
                function_checks.push_str(" AND NOT has_function_privilege(current_user, '");
                function_checks.push_str(function);
                function_checks.push_str("', 'EXECUTE')");
            }
        }
    }
    let mut cross_membership = String::new();
    for role in RUNTIME_ROLES {
        if *role != expected_role {
            cross_membership.push_str(" AND NOT COALESCE(pg_has_role(current_user, to_regrole('");
            cross_membership.push_str(role);
            cross_membership.push_str("'), 'MEMBER'), false)");
        }
    }

    let mut table_checks = String::new();
    if identity_reader {
        table_checks.push_str(" AND has_schema_privilege(current_user, 'identity', 'USAGE')");
    } else {
        table_checks.push_str(" AND has_schema_privilege(current_user, 'messaging', 'USAGE')");
    }
    if identity_reader {
        // Identity auth must not have messaging schema USAGE.  Avoid
        // qualified has_table_privilege calls because PostgreSQL raises 42501
        // when the schema itself is inaccessible.
        table_checks.push_str(" AND NOT has_schema_privilege(current_user, 'messaging', 'USAGE')");
        for table in [
            "identity.device_sessions",
            "identity.log_heads",
            "identity.log_entries",
        ] {
            table_checks.push_str(" AND has_table_privilege(current_user, '");
            table_checks.push_str(table);
            table_checks.push_str("', 'SELECT')");
            table_checks.push_str(" AND NOT has_table_privilege(current_user, '");
            table_checks.push_str(table);
            table_checks.push_str("', 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')");
        }
    } else {
        for table in PUSH_TABLES {
            table_checks.push_str(" AND NOT has_table_privilege(current_user, '");
            table_checks.push_str(table);
            table_checks.push_str("', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')");
        }
        // Non-identity runtimes must not even have identity schema USAGE.  Do
        // not call has_table_privilege here: PostgreSQL raises 42501 when a
        // role without schema USAGE asks about a qualified identity table.
        table_checks.push_str(" AND NOT has_schema_privilege(current_user, 'identity', 'USAGE')");
    }
    format!(
        "SELECT current_user = $1 AND session_user = $1 \
          AND pg_has_role(current_user, '{expected_role}', 'MEMBER') \
          AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreatedb AND NOT r.rolcreaterole \
          AND NOT has_schema_privilege(current_user, 'identity', 'CREATE') \
          AND NOT has_schema_privilege(current_user, 'messaging', 'CREATE') \
          AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
                          WHERE c.relowner=to_regrole(current_user)\
                            AND n.nspname IN ('identity','messaging')) \
          {cross_membership}{function_checks}{table_checks} \
          AND NOT rt.rolcanlogin \
          FROM pg_roles r JOIN pg_roles rt ON rt.rolname='{expected_role}' \
          WHERE r.rolname=current_user"
    )
}

#[cfg(test)]
pub(crate) fn validation_query_for_tests(
    expected_role: &'static str,
    approved_functions: &[&'static str],
    identity_reader: bool,
) -> String {
    validation_query(expected_role, approved_functions, identity_reader)
}

async fn validate_connection(
    connection: &mut sqlx::PgConnection,
    expected_login: &str,
    expected_role: &'static str,
    approved_functions: &[&'static str],
    identity_reader: bool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(validation_query(
        expected_role,
        approved_functions,
        identity_reader,
    )))
    .bind(expected_login)
    .fetch_one(&mut *connection)
    .await
}

fn validation_failure() -> sqlx::Error {
    sqlx::Error::Protocol("push runtime connection validation failed".to_owned())
}

async fn connect_and_validate(
    options: PgConnectOptions,
    max_connections: u32,
    expected_login: String,
    expected_role: &'static str,
    approved_functions: &[&'static str],
    identity_reader: bool,
) -> Result<PgPool, PushPostgresError> {
    let login_after = expected_login.clone();
    let role_after = expected_role;
    let functions_after = approved_functions.to_vec();
    let functions_before = approved_functions.to_vec();
    let pool = PgPoolOptions::new()
        .max_connections(max_connections.max(1))
        .after_connect(move |connection, _meta| {
            let expected_login = login_after.clone();
            let functions = functions_after.clone();
            Box::pin(async move {
                if !validate_connection(
                    connection,
                    &expected_login,
                    role_after,
                    &functions,
                    identity_reader,
                )
                .await?
                {
                    return Err(validation_failure());
                }
                Ok(())
            })
        })
        .before_acquire(move |connection, _meta| {
            let expected_login = expected_login.clone();
            let functions = functions_before.clone();
            Box::pin(async move {
                validate_connection(
                    connection,
                    &expected_login,
                    expected_role,
                    &functions,
                    identity_reader,
                )
                .await
            })
        })
        .connect_with(options)
        .await?;
    Ok(pool)
}

macro_rules! pool_wrapper {
    ($name:ident, $role:literal, [$($function:literal),* $(,)?], $identity:literal) => {
        #[derive(Clone)]
        pub struct $name { pool: PgPool }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).field("pool", &self.pool).finish()
            }
        }
        impl $name {
            pub async fn connect(options: PgConnectOptions, max_connections: u32, expected_login: impl Into<String>) -> Result<Self, PushPostgresError> {
                Ok(Self { pool: connect_and_validate(options, max_connections, expected_login.into(), $role, &[$($function),*], $identity).await? })
            }
            pub(crate) fn pool(&self) -> &PgPool { &self.pool }
        }
    };
}

pool_wrapper!(IdentityAuthPool, "dtx_push_identity_auth_runtime", [], true);
pool_wrapper!(
    RegistrationPool,
    "dtx_push_registration_runtime",
    [
        "messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid)",
        "messaging.opaque_push_commit_put(uuid,bytea,uuid,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea,bytea,bytea,bytea,text,bytea)",
        "messaging.opaque_push_commit_delete(uuid,bytea,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea)"
    ],
    false
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_query_fences_session_authorization_and_cross_membership() {
        let query = validation_query(
            "dtx_push_broker_runtime",
            &["messaging.claim_opaque_push_deliveries(uuid,integer)"],
            false,
        );
        assert!(query.contains("current_user = $1 AND session_user = $1"));
        assert!(query.contains("NOT COALESCE(pg_has_role(current_user, to_regrole("));
        assert!(query.contains("NOT rt.rolcanlogin"));
        assert!(query.contains("NOT has_table_privilege"));
    }
}
pool_wrapper!(
    BrokerPool,
    "dtx_push_broker_runtime",
    [
        "messaging.claim_opaque_push_deliveries(uuid,integer)",
        "messaging.prune_opaque_push_terminal(integer)",
        "messaging.authorize_opaque_push_send(uuid,uuid)",
        "messaging.finish_opaque_push_accepted(uuid,uuid)",
        "messaging.finish_opaque_push_permanent_failure(uuid,uuid,text)",
        "messaging.finish_opaque_push_transient(uuid,uuid,integer,text)",
        "messaging.finish_opaque_push_invalid_token(uuid,uuid,bigint)"
    ],
    false
);
