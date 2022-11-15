CREATE OR REPLACE FUNCTION public.current_inherited_roles(which_role name DEFAULT CURRENT_USER)
 RETURNS varchar[]
 LANGUAGE plpgsql
AS $function$
/* Author: Mihail.Gershkovich@gmail.com
 * Source: https://github.com/Karlodun/postgresql_addons/auto_acl_policy
 * Licence: 
 */
DECLARE
    current_inherited_roles varchar[];
BEGIN
    WITH RECURSIVE cte AS (
    SELECT pg_roles.oid,
            pg_roles.rolname
           FROM pg_roles
          WHERE pg_roles.rolname = which_role
          UNION
         SELECT m.roleid,
            pgr.rolname
           FROM cte cte_1
             JOIN pg_auth_members m ON m.member = cte_1.oid
             JOIN pg_roles pgr ON pgr.oid = m.roleid
        )
 SELECT array_agg(cte.rolname::varchar) into current_inherited_roles
   FROM cte
  WHERE NOT (cte.rolname ~~ 'pg_%'::text OR cte.rolname ~~ 'rds_%'::text OR cte.rolname = 'postgres'::name);
RETURN current_inherited_roles;
END;
$function$
;

DROP TABLE acl_test;

CREATE TABLE acl_test (id serial, reader_acl varchar[], writer_acl varchar[]);

ALTER TABLE acl_test DROP COLUMN writer_acl cascade;
ALTER TABLE acl_test ADD COLUMN writer_acl varchar[];

CREATE OR REPLACE FUNCTION auto_acl_policy()
 RETURNS event_trigger
 LANGUAGE plpgsql AS
$$
DECLARE
  r record;
  runner_sql TEXT;
BEGIN
FOR r IN SELECT * FROM pg_event_trigger_ddl_commands()
WHERE command_tag ~ '(CREATE|ALTER) TABLE'
LOOP

SELECT 'ALTER TABLE '||(table_schema||'.'||table_name)::regclass||' ENABLE ROW LEVEL SECURITY;'
INTO runner_sql
FROM information_schema."columns" c
JOIN pg_catalog.pg_tables pgt ON (pgt.schemaname||'.'||pgt.tablename)::regclass=(table_schema||'.'||table_name)::regclass
WHERE (table_schema||'.'||table_name)::regclass=r.object_identity::regclass
--WHERE (table_schema||'.'||table_name)::regclass='acl_test'::regclass
AND c.column_name ~'(reader|writer)_acl'
AND NOT pgt.rowsecurity
GROUP BY (table_schema||'.'||table_name)::regclass, pgt.rowsecurity;
IF runner_sql NOTNULL THEN
--    RAISE NOTICE 'runner: %', runner_sql;
    EXECUTE runner_sql;
END IF;

SELECT 'CREATE POLICY reader_acl ON '||(table_schema||'.'||table_name)::regclass||'
        AS PERMISSIVE
        FOR SELECT
        TO public
        USING (reader_acl ISNULL OR current_inherited_roles() && reader_acl);'
INTO runner_sql
FROM information_schema."columns" c
JOIN pg_catalog.pg_tables pgt ON (pgt.schemaname||'.'||pgt.tablename)::regclass=(table_schema||'.'||table_name)::regclass
LEFT JOIN pg_catalog.pg_policies pgp
    ON (pgp.schemaname||'.'||pgp.tablename)::regclass=(table_schema||'.'||table_name)::regclass
    AND pgp.policyname = c.column_name
WHERE (table_schema||'.'||table_name)::regclass=r.object_identity::regclass
--WHERE (table_schema||'.'||table_name)::regclass='acl_test'::regclass
AND c.column_name ='reader_acl'
AND pgt.rowsecurity
AND pgp.policyname ISNULL
GROUP BY (table_schema||'.'||table_name)::regclass, pgt.rowsecurity;
IF runner_sql NOTNULL THEN
--    RAISE NOTICE 'runner: %', runner_sql;
    EXECUTE runner_sql;
END IF;

SELECT 'CREATE POLICY writer_acl ON '||(table_schema||'.'||table_name)::regclass||'
        AS PERMISSIVE
        FOR SELECT
        TO public
        USING (writer_acl ISNULL OR current_inherited_roles() && writer_acl);'
INTO runner_sql
FROM information_schema."columns" c
JOIN pg_catalog.pg_tables pgt ON (pgt.schemaname||'.'||pgt.tablename)::regclass=(table_schema||'.'||table_name)::regclass
LEFT JOIN pg_catalog.pg_policies pgp
    ON (pgp.schemaname||'.'||pgp.tablename)::regclass=(table_schema||'.'||table_name)::regclass
    AND pgp.policyname = c.column_name
WHERE (table_schema||'.'||table_name)::regclass=r.object_identity::regclass
--WHERE (table_schema||'.'||table_name)::regclass='acl_test'::regclass
AND c.column_name ='writer_acl'
AND pgt.rowsecurity
AND pgp.policyname ISNULL
GROUP BY (table_schema||'.'||table_name)::regclass, pgt.rowsecurity;
IF runner_sql NOTNULL THEN
--    RAISE NOTICE 'runner: %', runner_sql;
    EXECUTE runner_sql;
END IF;

END LOOP;

END;
$$;

CREATE EVENT TRIGGER auto_acl_policy
    ON ddl_command_end 
    WHEN TAG IN ('CREATE TABLE', 'ALTER TABLE')
    EXECUTE FUNCTION auto_acl_policy();
