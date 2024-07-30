-- protect script from being sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION ekorre" to load this file. \quit

CREATE FUNCTION ekorre_handler() RETURNS fdw_handler
AS 'MODULE_PATHNAME' LANGUAGE C STRICT;

CREATE FUNCTION ekorre_validator(text[], oid) RETURNS void
AS 'MODULE_PATHNAME' LANGUAGE C STRICT;

CREATE FOREIGN DATA WRAPPER ekorre
HANDLER ekorre_handler
VALIDATOR ekorre_validator;
