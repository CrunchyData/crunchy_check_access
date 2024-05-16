create or replace function @extschema@.check_grants
(
  in luser text,
  in incl_sys bool,
  inout role_path text,
  out base_role text,
  out as_role text,
  out objtype text,
  out objid oid,
  out schemaname text,
  out objname text,
  out privname text,
  out grantable bool
) returns setof record
as $$
  declare
    schemaoid        oid;
    colnum           int;
    colrelname       text;
    colname          text;
    minatt           text;
    priv             text;
    grantopt         text:= ' WITH GRANT OPTION';
    grpname          text;
    inh              text;
    brole_path       text;
    rec              record;

    db_privs         text[] := ARRAY['CREATE', 'CONNECT', 'TEMPORARY', 'TEMP'];
    tblspc_privs     text[] := ARRAY['CREATE'];
    fdw_privs        text[] := ARRAY['USAGE'];
    fdwsrv_privs     text[] := ARRAY['USAGE'];
    lang_privs       text[] := ARRAY['USAGE'];
    schema_privs     text[] := ARRAY['CREATE', 'USAGE'];
    table_privs      text[] := ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'];
    column_privs     text[] := ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES'];
    seq_privs        text[] := ARRAY['USAGE', 'SELECT', 'UPDATE'];
    func_privs       text[] := ARRAY['EXECUTE'];
    with_grant       text[] := ARRAY['', ' WITH GRANT OPTION'];

    schemas_to_skip  text;

  begin
    schemaname := NULL;

    if (role_path is null) then
      role_path := luser;
    end if;

    base_role := luser;
    as_role := luser;

    if (incl_sys) then
      schemas_to_skip := '';
    else
      schemas_to_skip := $_$ where n.nspname !~ '^pg_' AND n.nspname not in ('information_schema')$_$;
    end if;

    -- check database privs
    objtype := 'database';
    objid := oid from pg_database where datname = current_database();
    objname := current_database()::text;
    foreach priv in array db_privs loop
        if (has_database_privilege(luser, current_database(), priv)) then
            privname := priv;
            grantable := has_database_privilege(luser, current_database(), priv || grantopt);
            return next;
        end if;
    end loop;

    -- check tablespace privs
    objtype := 'tablespace';
    for objid, objname in select t.oid, t.spcname from pg_catalog.pg_tablespace t where t.spcname !~ '^pg_' order by 2,1 loop
       foreach priv in array tblspc_privs loop
          if (has_tablespace_privilege(luser, objname, priv)) then
            privname := priv;
            grantable := has_database_privilege(luser, objname, priv || grantopt);
            return next;
          end if;
      end loop;
    end loop;

    -- check foreign data wrapper privs
    objtype := 'fdw';
    for objid, objname in select f.oid, f.fdwname from pg_catalog.pg_foreign_data_wrapper f order by 2,1 loop
        foreach priv in array fdw_privs loop
          if (has_foreign_data_wrapper_privilege(luser, objname, priv)) then
            privname := priv;
            grantable  := has_foreign_data_wrapper_privilege(luser, objname, priv || grantopt);
            return next;
          end if;
        end loop;
    end loop;

    -- check foreign server privs
    objtype := 'server';
    for objid, objname in select s.oid, s.srvname from pg_catalog.pg_foreign_server s order by 2,1 loop
        foreach priv in array fdwsrv_privs loop
          if (has_server_privilege(luser, objname, priv)) then
            privname := priv;
            grantable := has_server_privilege(luser, objname, priv || grantopt);
            return next;
          end if;
        end loop;
    end loop;

    -- check language privs
    objtype := 'language';
    for objid, objname in select l.oid, l.lanname from pg_catalog.pg_language l order by 2,1 loop
        foreach priv in array lang_privs loop
          if (has_language_privilege(luser, objname, priv)) then
            -- still might not be true ...
            -- if a superuser, or language is trusted, we really do have access
            if ((select rolsuper from pg_catalog.pg_authid where rolname = luser) or
                (select l.lanpltrusted from pg_catalog.pg_language l where l.oid = objid)) then
              privname := priv;
              grantable := has_language_privilege(luser, objname, priv || grantopt);
              return next;
            end if;
          end if;
        end loop;
    end loop;

    -- check schema privs
    for schemaoid, schemaname in execute 'select n.oid, n.nspname::text from pg_catalog.pg_namespace n' || schemas_to_skip || ' order by 2,1' loop
      objtype := 'schema';
      objid := schemaoid;
      objname := schemaname;
        foreach priv in array schema_privs loop
          if (has_schema_privilege(luser, schemaname, priv)) then
            privname := priv;
            grantable := has_schema_privilege(luser, schemaname, priv || grantopt);
            return next;
          end if;
        end loop;

      -- check function privs
      objtype := 'function';
      for objid, objname in select p.oid, p.proname || '(' || proargtypes::text || ')' from pg_catalog.pg_proc p where p.pronamespace = schemaoid order by 2,1 loop
          foreach priv in array func_privs loop
            if (has_function_privilege(luser, objid, priv)) then
              privname := priv;
              grantable := has_function_privilege(luser, objid, priv || grantopt);
              return next;
            end if;
          end loop;
      end loop;

      -- check table privs
      for objid, objname in select c.oid, c.relname from pg_catalog.pg_class c where c.relnamespace = schemaoid and relkind in ('r') order by 2,1 loop
          foreach priv in array table_privs loop
            if (has_table_privilege(luser, objid, priv)) then
              objtype := 'table';
              privname := priv;
              grantable := has_table_privilege(luser, objid, priv || grantopt);
              return next;
            else
              if priv = ANY (column_privs) then
                colrelname := objname;
                objtype := 'table.column';
                if (has_any_column_privilege(luser, objid, priv)) then
                  if (incl_sys) then
                    minatt = ''; -- arbitrary, but ought to work for the forseeable future
                  else
                    minatt = ' and a.attnum > 0'; -- show only user columns
                  end if;
                  for colnum, colname in execute
                      'select a.attnum, a.attname from pg_catalog.pg_attribute a where a.attrelid = ' || objid::text || minatt || ' order by 1,2' loop
                    if (has_column_privilege(luser, objid, colname, priv)) then
                      objname := colrelname || '.' || colname;
                      privname := priv;
                      grantable := has_any_column_privilege(luser, objid, priv || grantopt);
                      return next;
                    end if;
                  end loop;
                end if;
                objname := colrelname;
              end if;
            end if;
          end loop;
      end loop;

      -- check view privs
      for objid, objname in select c.oid, c.relname from pg_catalog.pg_class c where c.relnamespace = schemaoid and relkind in ('v') order by 2,1 loop
          foreach priv in array table_privs loop
            if (has_table_privilege(luser, objid, priv)) then
              objtype := 'view';
              privname := priv;
              grantable := has_table_privilege(luser, objid, priv || grantopt);
              return next;
            else
              if priv = ANY (column_privs) then
                colrelname := objname;
                objtype := 'view.column';
                if (has_any_column_privilege(luser, objid, priv)) then
                  minatt = ' and a.attnum > 0'; -- VIEWs have no system columns
                  for colnum, colname in execute
                      'select a.attnum, a.attname from pg_catalog.pg_attribute a where a.attrelid = ' || objid::text || minatt || ' order by 1,2' loop
                    if (has_column_privilege(luser, objid, colname, priv)) then
                      objname := colrelname || '.' || colname;
                      privname := priv;
                      grantable := has_column_privilege(luser, objid, colname, priv || grantopt);
                      return next;
                    end if;
                  end loop;
                end if;
                objname := colrelname;
              end if;
            end if;
          end loop;
      end loop;

      -- check seq privs
      objtype := 'sequence';
      for objid, objname in select c.oid, c.relname from pg_catalog.pg_class c where c.relnamespace = schemaoid and relkind in ('S') order by 2,1 loop
          foreach priv in array seq_privs loop
            if (has_sequence_privilege(luser, objid, priv)) then
              privname := priv;
              grantable := has_sequence_privilege(luser, objid, priv || grantopt);
              return next;
            end if;
          end loop;
      end loop;

    end loop;

    -- recurse into any granted roles
    brole_path := role_path;
    for grpname, inh in select a.rolname as group, '(' || u.rolinherit || ')' from pg_catalog.pg_authid a join pg_catalog.pg_auth_members m on a.oid = m.roleid join pg_authid u on m.member = u.oid where u.rolname = luser loop
      role_path := brole_path || inh || '.' || grpname;
      for rec in select * from @extschema@.check_grants(grpname, incl_sys, role_path) loop
        as_role := rec.as_role;
        role_path := rec.role_path;
        objtype := rec.objtype;
        objid := rec.objid;
        schemaname := rec.schemaname;
        objname := rec.objname;
        privname := rec.privname;
        grantable := rec.grantable;
        return next;
      end loop;
    end loop;

    return;
  end;
$$ language plpgsql;

revoke execute on function @extschema@.check_grants(text, bool, text) from public;

create or replace function @extschema@.check_grants
(
  in luser text,
  in incl_sys bool,
  out role_path text,
  out base_role text,
  out as_role text,
  out objtype text,
  out objid oid,
  out schemaname text,
  out objname text,
  out privname text,
  out grantable bool
)
returns setof record
as $$
  select * from @extschema@.check_grants($1, $2, NULL);
$$ language sql;

revoke execute on function @extschema@.check_grants(text, bool) from public;

create or replace function @extschema@.all_grants
(
  in incl_sys bool,
  out role_path text,
  out base_role text,
  out as_role text,
  out objtype text,
  out objid oid,
  out schemaname text,
  out objname text,
  out privname text,
  out grantable bool
)
returns setof record
as $$
  declare
    rec              record;
    rname            text;
  begin
    for rname in select a.rolname as group from pg_catalog.pg_authid a order by 1 loop
      for role_path, base_role, as_role, objtype, objid, schemaname, objname, privname, grantable in select * from @extschema@.check_grants(rname, incl_sys) loop
        return next;
      end loop;
    end loop;
    return;
  end;
$$ language plpgsql;

revoke execute on function @extschema@.all_grants(bool) from public;

create or replace function @extschema@.all_grants
(
  out role_path text,
  out base_role text,
  out as_role text,
  out objtype text,
  out objid oid,
  out schemaname text,
  out objname text,
  out privname text,
  out grantable bool
)
returns setof record
as $$
  select * from @extschema@.all_grants(false)
$$ language sql;

revoke execute on function @extschema@.all_grants() from public;
