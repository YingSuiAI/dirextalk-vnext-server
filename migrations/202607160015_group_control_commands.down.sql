DO $revoke$
BEGIN
    IF to_regrole('dtx_group_runtime') IS NOT NULL THEN
        REVOKE ALL ON groups.control_commands FROM dtx_group_runtime;
    END IF;
END
$revoke$;

DROP TABLE groups.control_commands;
