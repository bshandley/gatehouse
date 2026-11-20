/**
 * SQL for the passthrough alias, shared by initDB (the unique index) and
 * SecretsEngine.findByAlias (the lookup) so the indexed expression and the
 * queried expression cannot drift. json_valid guards rows whose metadata is
 * not valid JSON, which would otherwise make json_extract raise.
 */
export const ALIAS_EXPR =
  "CASE WHEN json_valid(metadata) THEN json_extract(metadata, '$.passthrough_alias') END";

export const ALIAS_PREDICATE = `${ALIAS_EXPR} IS NOT NULL AND ${ALIAS_EXPR} != ''`;

export const ALIAS_INDEX_NAME = "idx_secrets_passthrough_alias";

export const CREATE_ALIAS_INDEX_SQL = `CREATE UNIQUE INDEX IF NOT EXISTS ${ALIAS_INDEX_NAME}
  ON secrets(${ALIAS_EXPR}) WHERE ${ALIAS_PREDICATE}`;

/** Aliases held by more than one row. */
export const DUPLICATE_ALIASES_SQL = `SELECT ${ALIAS_EXPR} AS alias FROM secrets
  WHERE ${ALIAS_PREDICATE} GROUP BY ${ALIAS_EXPR} HAVING COUNT(*) > 1`;

/** LIMIT 2 so a duplicate is detectable without scanning further. */
export const FIND_BY_ALIAS_SQL = `SELECT path, metadata, version, created_at, updated_at, last_accessed_at FROM secrets
  WHERE ${ALIAS_EXPR} = ? AND ${ALIAS_PREDICATE} LIMIT 2`;
