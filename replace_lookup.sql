CREATE OR REPLACE FUNCTION public.replace_lookup(
    source_array anyarray, lookup_table regclass, lookup_column varchar, lookup_value varchar, lookup_filter varchar DEFAULT 'true'
    )
 RETURNS varchar[]
 LANGUAGE SQL AS
$$
    WITH source_values as (SELECT UNNEST($1) source_value)
    SELECT array_agg(replace_lookup(source_value,$2,$3,$4,$5))
    FROM source_values
    ;
$$
;
    
CREATE OR REPLACE FUNCTION public.replace_lookup(
    source_value anynonarray, lookup_table regclass, lookup_column varchar, lookup_value varchar, lookup_filter varchar DEFAULT 'true'
    )
-- https://www.postgresql.org/docs/current/datatype-pseudo.html
 RETURNS varchar
 LANGUAGE plpgsql
AS $function$
DECLARE
    runner_sql text;
    res varchar;
BEGIN
runner_sql := 'SELECT '||lookup_value||' FROM '||lookup_table||'
WHERE '||source_value||'='||lookup_column||' AND ('||lookup_filter||');';
--    RAISE NOTICE '%', runner_sql;
EXECUTE runner_sql INTO res;
RETURN res;
END;
$function$
;
