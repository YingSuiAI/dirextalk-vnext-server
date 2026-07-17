-- PD3d gives every logical Indexer a durable, monotonic search projection
-- generation. Public replicas probe this narrow row before consulting their
-- local body cache, so a successful publish/revoke cannot remain hidden until
-- an unrelated process-local TTL expires.
CREATE TABLE directory.index_cache_generations (
  tenant_id uuid NOT NULL,
  indexer_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  updated_at_ms bigint NOT NULL,
  PRIMARY KEY (tenant_id, indexer_id),
  CHECK (system.is_uuid_v7(indexer_id))
);

INSERT INTO directory.index_cache_generations (tenant_id, indexer_id, generation, updated_at_ms)
SELECT tenant_id, indexer_id, 1, max(updated_at_ms)
FROM directory.index_registrations
WHERE status IN (2, 5)
GROUP BY tenant_id, indexer_id;

ALTER TABLE directory.index_cache_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE directory.index_cache_generations FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_tenant_only ON directory.index_cache_generations
USING (
  directory.public_feed_owner_authorized()
  OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())
)
WITH CHECK (
  directory.public_feed_owner_authorized()
  OR (directory.public_feed_runtime_authorized() AND tenant_id=directory.current_tenant_id())
);

DO $grant$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NOT NULL THEN
  GRANT SELECT,INSERT,UPDATE ON directory.index_cache_generations TO dtx_public_feed_runtime;
END IF; END $grant$;
REVOKE ALL ON directory.index_cache_generations FROM PUBLIC;
