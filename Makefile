MODULES = ekorre
MODULE_big = ekorre

SHLIB_LINK = -lgit2
EXTENSION = ekorre
OBJS = ekorre.o
DATA = ekorre--1.0.0.sql
PGFILEDESC = "ekorre - Git repository foreign data wrapper"
PG_CONFIG = $(shell which pg_config)

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
