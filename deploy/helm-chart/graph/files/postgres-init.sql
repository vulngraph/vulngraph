-- The roles of the bundled Postgres, in both the Helm chart and
-- deploy/docker-compose. The postgres image runs this file once, as its
-- bootstrap superuser, when it initialises an empty data directory
-- (/docker-entrypoint-initdb.d).
--
-- migrate, serve and the worker connect as graph. It owns the graph database,
-- so migrate can apply the schema and River's job tables, and River's
-- maintenance can reindex them (REINDEX needs the owner). It is not a
-- superuser and holds none of the pg_*_server_* roles, so it cannot read or
-- write server files or run programs on the database host (COPY ... TO
-- PROGRAM), and it cannot create roles or databases.
--
-- The scanner connects as graph_scanner, which owns nothing. Its grants cannot
-- be made here: this runs before migrate has created the tables, and they are
-- graph's to grant. migrate grants them after every run
-- (internal/migrate/scanner.go): River's job tables and the scan tables, and
-- nothing on users, API keys or connectors.
--
-- GRAPH_DB_PASSWORD and GRAPH_SCANNER_DB_PASSWORD are their passwords. When
-- one is unset its :'...' stays literal, the CREATE ROLE is a syntax error and
-- the bootstrap stops: no role is created without a password.
\set ON_ERROR_STOP on
\getenv graph_password GRAPH_DB_PASSWORD
\getenv scanner_password GRAPH_SCANNER_DB_PASSWORD
CREATE ROLE graph LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'graph_password';
CREATE ROLE graph_scanner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'scanner_password';
ALTER DATABASE graph OWNER TO graph;
