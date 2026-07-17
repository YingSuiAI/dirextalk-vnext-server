-- MCP ReferenceV1 reuses authoritative group membership and signed PublicFeed
-- facts without granting the Agent runtime direct table access.

CREATE FUNCTION groups.mcp_visible_private_conversations(
    requested_tenant_id uuid,
    requested_identity_id text,
    requested_query text,
    requested_limit integer
)
RETURNS TABLE(scope_id text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, groups, system
AS $$
BEGIN
    IF requested_tenant_id IS DISTINCT FROM system.current_tenant_id()
        OR requested_identity_id !~ '^dtxi1[a-z2-7]{52}$'
        OR octet_length(requested_query) > 256
        OR requested_limit NOT BETWEEN 1 AND 32
    THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT policy.scope_id
      FROM groups.policy_heads AS policy
     WHERE policy.tenant_id = requested_tenant_id
       AND policy.scope_kind = 'private_conversation'
       AND (
            policy.owner_identity_id = requested_identity_id
            OR EXISTS (
                SELECT 1
                  FROM groups.members AS member
                 WHERE member.tenant_id = policy.tenant_id
                   AND member.scope_kind = policy.scope_kind
                   AND member.scope_id = policy.scope_id
                   AND member.identity_id = requested_identity_id
            )
       )
       AND (
            requested_query = ''
            OR strpos(lower(policy.scope_id), lower(requested_query)) > 0
       )
     ORDER BY policy.scope_id
     LIMIT requested_limit;
END
$$;

CREATE FUNCTION directory.mcp_public_reference_facts(
    requested_tenant_id uuid,
    requested_kind_mask integer,
    requested_scan_limit integer,
    requested_now_ms bigint
)
RETURNS TABLE(
    reference_kind smallint,
    subject_id text,
    sequence bigint,
    exact_cbor bytea
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, directory, system
AS $$
BEGIN
    IF requested_tenant_id IS DISTINCT FROM system.current_tenant_id()
        OR requested_kind_mask < 1
        OR requested_kind_mask > 7
        OR (requested_kind_mask & ~6) <> 0
        OR requested_scan_limit NOT BETWEEN 1 AND 256
        OR requested_now_ms NOT BETWEEN 0 AND 253402300799999
    THEN
        RETURN;
    END IF;

    IF (requested_kind_mask & 2) <> 0 THEN
        RETURN QUERY
        SELECT 2::smallint, subject.subject_id, NULL::bigint, NULL::bytea
          FROM directory.public_subjects AS subject
         WHERE subject.tenant_id = requested_tenant_id
           AND subject.subject_kind = 1
           AND NOT subject.descriptor_tombstoned
           AND subject.descriptor_expires_at_ms > requested_now_ms
         ORDER BY subject.subject_id
         LIMIT requested_scan_limit;
    END IF;

    IF (requested_kind_mask & 4) <> 0 THEN
        RETURN QUERY
        SELECT 3::smallint, entry.subject_id, entry.sequence, entry.exact_cbor
          FROM directory.feed_entries AS entry
          JOIN directory.public_subjects AS subject
            ON subject.tenant_id = entry.tenant_id
           AND subject.subject_id = entry.subject_id
         WHERE entry.tenant_id = requested_tenant_id
           AND subject.subject_kind = 1
           AND NOT subject.descriptor_tombstoned
           AND subject.descriptor_expires_at_ms > requested_now_ms
           AND NOT subject.feed_tombstoned
           AND NOT entry.tombstone
         ORDER BY entry.subject_id, entry.sequence DESC
         LIMIT requested_scan_limit;
    END IF;
END
$$;

REVOKE ALL ON FUNCTION groups.mcp_visible_private_conversations(uuid, text, text, integer)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION directory.mcp_public_reference_facts(uuid, integer, integer, bigint)
    FROM PUBLIC;

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA groups, directory TO dtx_agent_runtime;
        GRANT EXECUTE ON FUNCTION
            groups.mcp_visible_private_conversations(uuid, text, text, integer),
            directory.mcp_public_reference_facts(uuid, integer, integer, bigint)
            TO dtx_agent_runtime;
    END IF;
END
$grant$;
