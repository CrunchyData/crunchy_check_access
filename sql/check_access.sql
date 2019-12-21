/*
 * 
 * Copyright 2015-2019 Crunchy Data Solutions, Inc.
 * Copyright 2009-2015 Joe Conway <mail@joeconway.com>
 * 
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without a written agreement
 * is hereby granted, provided that the above copyright notice and this
 * paragraph and the following two paragraphs appear in all copies.
 *
 * IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
 * DOCUMENTATION, EVEN IF THE AUTHOR OR DISTRIBUTORS HAVE BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUTHOR AND DISTRIBUTORS HAS NO OBLIGATIONS TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 *
 */

create or replace function check_access
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
  out privname text
) returns setof record
as $$
  declare
    schemaoid        oid;
    colnum           int;
    colrelname       text;
    colname          text;
    minatt           text;
    priv             text;
    grantopt         text;
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

-- domain privs? USAGE
-- large object privs? SELECT | UPDATE
-- has_type_privilege? USAGE

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
    foreach grantopt in array with_grant loop
      foreach priv in array db_privs loop
        if (has_database_privilege(luser, current_database(), priv || grantopt)) then
          privname := priv || grantopt;
          return next;
        end if;
      end loop;
    end loop;

    -- check tablespace privs
    objtype := 'tablespace';
    for objid, objname in select t.oid, t.spcname from pg_catalog.pg_tablespace t where t.spcname !~ '^pg_' order by 2,1 loop
      foreach grantopt in array with_grant loop
        foreach priv in array tblspc_privs loop
          if (has_tablespace_privilege(luser, objname, priv || grantopt)) then
            privname := priv || grantopt;
            return next;
          end if;
        end loop;
      end loop;
    end loop;

    -- check foreign data wrapper privs
    objtype := 'fdw';
    for objid, objname in select f.oid, f.fdwname from pg_catalog.pg_foreign_data_wrapper f order by 2,1 loop
      foreach grantopt in array with_grant loop
        foreach priv in array fdw_privs loop
          if (has_foreign_data_wrapper_privilege(luser, objname, priv || grantopt)) then
            privname := priv || grantopt;
            return next;
          end if;
        end loop;
      end loop;
    end loop;

    -- check foreign server privs
    objtype := 'server';
    for objid, objname in select s.oid, s.srvname from pg_catalog.pg_foreign_server s order by 2,1 loop
      foreach grantopt in array with_grant loop
        foreach priv in array fdwsrv_privs loop
          if (has_server_privilege(luser, objname, priv || grantopt)) then
            privname := priv || grantopt;
            return next;
          end if;
        end loop;
      end loop;
    end loop;

    -- check language privs
    objtype := 'language';
    for objid, objname in select l.oid, l.lanname from pg_catalog.pg_language l order by 2,1 loop
      foreach grantopt in array with_grant loop
        foreach priv in array lang_privs loop
          if (has_language_privilege(luser, objname, priv || grantopt)) then
            -- still might not be true ...
            -- if a superuser, or language is trusted, we really do have access
            if ((select rolsuper from pg_catalog.pg_authid where rolname = luser) or
                (select l.lanpltrusted from pg_catalog.pg_language l where l.oid = objid)) then
              privname := priv || grantopt;
              return next;
            end if;
          end if;
        end loop;
      end loop;
    end loop;

    -- check schema privs
    for schemaoid, schemaname in execute 'select n.oid, n.nspname::text from pg_catalog.pg_namespace n' || schemas_to_skip || ' order by 2,1' loop
      objtype := 'schema';
      objid := schemaoid;
      objname := schemaname;
      foreach grantopt in array with_grant loop
        foreach priv in array schema_privs loop
          if (has_schema_privilege(luser, schemaname, priv || grantopt)) then
            privname := priv || grantopt;
            return next;
          end if;
        end loop;
      end loop;

      if (has_schema_privilege(luser, schemaname, 'usage')) then

        -- check function privs
        objtype := 'function';
        for objid, objname in select p.oid, p.proname || '(' || proargtypes::text || ')' from pg_catalog.pg_proc p where p.pronamespace = schemaoid order by 2,1 loop
          foreach grantopt in array with_grant loop
            foreach priv in array func_privs loop
              if (has_function_privilege(luser, objid, priv || grantopt)) then
                privname := priv || grantopt;
                return next;
              end if;
            end loop;
          end loop;
        end loop;

        -- check table privs
        for objid, objname in select c.oid, c.relname from pg_catalog.pg_class c where c.relnamespace = schemaoid and relkind in ('r') order by 2,1 loop
          foreach grantopt in array with_grant loop
            foreach priv in array table_privs loop
              if (has_table_privilege(luser, objid, priv || grantopt)) then
                objtype := 'table';
                privname := priv || grantopt;
                return next;
              else
                if priv = ANY (column_privs) then
                  colrelname := objname;
                  objtype := 'table.column';
                  if (has_any_column_privilege(luser, objid, priv || grantopt)) then
                    if (incl_sys) then
                      minatt = ''; -- arbitrary, but ought to work for the forseeable future
                    else
                      minatt = ' and a.attnum > 0'; -- show only user columns
                    end if;
                    for colnum, colname in execute
                        'select a.attnum, a.attname from pg_catalog.pg_attribute a where a.attrelid = ' || objid::text || minatt || ' order by 1,2' loop
                      if (has_column_privilege(luser, objid, colname, priv || grantopt)) then
                        objname := colrelname || '.' || colname;
                        privname := priv || grantopt;
                        return next;
                      end if;
                    end loop;
                  end if;
                  objname := colrelname;
                end if;
              end if;
            end loop;
          end loop;
        end loop;

        -- check view privs
        for objid, objname in select c.oid, c.relname from pg_catalog.pg_class c where c.relnamespace = schemaoid and relkind in ('v') order by 2,1 loop
          foreach grantopt in array with_grant loop
            foreach priv in array table_privs loop
              if (has_table_privilege(luser, objid, priv || grantopt)) then
                objtype := 'view';
                privname := priv || grantopt;
                return next;
              else
                if priv = ANY (column_privs) then
                  colrelname := objname;
                  objtype := 'view.column';
                  if (has_any_column_privilege(luser, objid, priv || grantopt)) then
                    minatt = ' and a.attnum > 0'; -- VIEWs have no system columns
                    for colnum, colname in execute
                        'select a.attnum, a.attname from pg_catalog.pg_attribute a where a.attrelid = ' || objid::text || minatt || ' order by 1,2' loop
                      if (has_column_privilege(luser, objid, colname, priv || grantopt)) then
                        objname := colrelname || '.' || colname;
                        privname := priv || grantopt;
                        return next;
                      end if;
                    end loop;
                  end if;
                  objname := colrelname;
                end if;
              end if;
            end loop;
          end loop;
        end loop;

        -- check seq privs
        objtype := 'sequence';
        for objid, objname in select c.oid, c.relname from pg_catalog.pg_class c where c.relnamespace = schemaoid and relkind in ('S') order by 2,1 loop
          foreach grantopt in array with_grant loop
            foreach priv in array seq_privs loop
              if (has_sequence_privilege(luser, objid, priv || grantopt)) then
                privname := priv || grantopt;
                return next;
              end if;
            end loop;
          end loop;
        end loop;

      end if;
    end loop;

    -- recurse into any granted roles
    brole_path := role_path;
    for grpname, inh in select a.rolname as group, '(' || u.rolinherit || ')' from pg_catalog.pg_authid a join pg_catalog.pg_auth_members m on a.oid = m.roleid join pg_authid u on m.member = u.oid where u.rolname = luser loop
      role_path := brole_path || inh || '.' || grpname;
      for rec in select * from check_access(grpname, incl_sys, role_path) loop
        as_role := rec.as_role;
        role_path := rec.role_path;
        objtype := rec.objtype;
        objid := rec.objid;
        schemaname := rec.schemaname;
        objname := rec.objname;
        privname := rec.privname;
        return next;
      end loop;
    end loop;

    return;
  end;
$$ language plpgsql;

revoke execute on function check_access(text, bool, text) from public;

create or replace function check_access
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
  out privname text
)
returns setof record
as $$
  select * from check_access($1, $2, NULL);
$$ language sql;

revoke execute on function check_access(text, bool) from public;

create or replace function all_access
(
  in incl_sys bool,
  out role_path text,
  out base_role text,
  out as_role text,
  out objtype text,
  out objid oid,
  out schemaname text,
  out objname text,
  out privname text
)
returns setof record
as $$
  declare
    rec              record;
    rname            text;
  begin
    for rname in select a.rolname as group from pg_catalog.pg_authid a order by 1 loop
      for role_path, base_role, as_role, objtype, objid, schemaname, objname, privname in select * from check_access(rname, incl_sys) loop
        return next;
      end loop;
    end loop;
    return;
  end;
$$ language plpgsql;

revoke execute on function all_access(bool) from public;

create or replace function all_access
(
  out role_path text,
  out base_role text,
  out as_role text,
  out objtype text,
  out objid oid,
  out schemaname text,
  out objname text,
  out privname text
)
returns setof record
as $$
  select * from all_access(false)
$$ language sql;

revoke execute on function all_access() from public;

create or replace function my_privs
(
  out role_path text,
  out base_role text,
  out as_role text,
  out objtype text,
  out objid oid,
  out schemaname text,
  out objname text,
  out privname text
)
returns setof record
SECURITY DEFINER
as $$
  select * from all_access(false) where base_role = SESSION_USER
$$ language sql;

grant execute on function my_privs() to public;

create or replace view my_privs as select * from my_privs();
grant select on my_privs to public;

create or replace function my_privs_sys
(
  out role_path text,
  out base_role text,
  out as_role text,
  out objtype text,
  out objid oid,
  out schemaname text,
  out objname text,
  out privname text
)
returns setof record
SECURITY DEFINER
as $$
  select * from all_access(true) where base_role = SESSION_USER
$$ language sql;

grant execute on function my_privs_sys() to public;

create or replace view my_privs_sys as select * from my_privs_sys();
grant select on my_privs_sys to public;

