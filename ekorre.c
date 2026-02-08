/*-------------------------------------------------------------------------
 * 
 * E K O R R E
 *
 *-------------------------------------------------------------------------
 *
 * Git foreign data wrapper for PostgreSQL.
 *
 * Copyright 2024 Daniel Gustafsson <daniel@yesql.se>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/reloptions.h"
#include "access/table.h"
#include "catalog/pg_foreign_table.h"
#include "catalog/pg_operator.h"
#include "commands/defrem.h"
#include "commands/explain.h"
#include "common/sha2.h"
#include "foreign/fdwapi.h"
#include "foreign/foreign.h"
#include "optimizer/optimizer.h"
#include "optimizer/pathnode.h"
#include "optimizer/planmain.h"
#include "optimizer/restrictinfo.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

#include <git2.h>

/*
 * git_log remote schema attributes
 */
#define Anum_git_log_commit_id 0
#define Anum_git_log_author_name 1
#define Anum_git_log_author_email 2
#define Anum_git_log_author_date 3
#define Anum_git_log_committer_name 4
#define Anum_git_log_committer_email 5
#define Anum_git_log_committer_date 6
#define Anum_git_log_summary 7
#define Anum_git_log_message 8
#define Anum_git_log_deltas 9
#define Anum_git_log_insertions 10
#define Anum_git_log_deletions 11
#define Anum_git_log_changed_files 12
#define Natts_git_log 12

/* Convert git_time to use PostgreSQL epoch */
#define PG_DATE(d) ((d) - ((POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY)) * USECS_PER_SEC

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(ekorre_handler);
PG_FUNCTION_INFO_V1(ekorre_validator);

/*
 * -------------------------------------------------------------------------
 * D A T A T Y P E S
 * -------------------------------------------------------------------------
 */
typedef struct EkorreExecutionState
{
	char	*repopath;
	char	*branch;
	git_repository *repo;
	git_revwalk *revwalker;
} EkorreExecutionState;

typedef struct EkorrePlanState
{
	char	*repopath;
	List	*options;

	double	ncommits;
	List   *restrictquals;
} EkorrePlanState;

/*
 * Option Handling
 */
struct EkorreOption
{
	const char *name;
	Oid			context;
};

static const struct EkorreOption valid_options[] = {
	/* Repository options */
	{"repopath", ForeignTableRelationId},

	/* Sentinel option */
	{NULL, InvalidOid}
};

typedef enum QualOp
{
	OP_UNSUPPORTED = -1,
	OP_EQ = 0,
	OP_GT,
	OP_LT,
	OP_GE,
	OP_LE
} QualOp;

/*
 * Restriction qualifier info for pushing down restriction clauses to the Git
 * repository scanning.
 */
typedef struct EkorreQualInfo
{
	int			varattno;			/* The attribute to restrict on */
	QualOp		op;
	union
	{
		Timestamp	constval_ts;
		char	   *constval_string;
		int64		constval_int;
	};

} EkorreQualInfo;


/*
 * -------------------------------------------------------------------------
 * P R O T O T Y P E S
 * -------------------------------------------------------------------------
 */

/* Prototypes for internal support functions  */
static void get_options(Oid foreignTableId, char **repopath);
static char *git_errmsg(void);

static void ekr_deparse_qual(Expr *node, EkorreQualInfo **qual);
static void ekr_deparse_opexpr(OpExpr *node, EkorreQualInfo **qual);
static void ekr_deparse_var(Var *node, EkorreQualInfo **qual);
static void ekr_deparse_const(Const *node, EkorreQualInfo **qual);

/* Prototypes for public API functions */
static void ekorreBeginForeignScan(ForeignScanState *node, int eflags);
static TupleTableSlot *ekorreIterateForeignScan(ForeignScanState *node);
static void ekorreReScanForeignScan(ForeignScanState *node);
static void ekorreEndForeignScan(ForeignScanState *node);
static void ekorreGetRelSize(PlannerInfo *root, RelOptInfo *baserel,
							 Oid foreigntableid);
static void ekorreGetForeignPaths(PlannerInfo *root, RelOptInfo *baserel,
								  Oid foreigntableid);
static ForeignScan *ekorreGetForeignPlan(PlannerInfo *root,
										 RelOptInfo *baserel,
										 Oid foreigntableid,
										 ForeignPath *best_path,
										 List *tlist,
										 List *scan_clauses,
										 Plan *outer_plan);
static void ekorreExplainForeignScan(ForeignScanState *node, ExplainState *es);
static bool ekorreAnalyzeForeignTable(Relation relation,
									  AcquireSampleRowsFunc *func,
									  BlockNumber *totalpages);
static bool ekorreIsForeignScanParallelSafe(PlannerInfo *root, RelOptInfo *rel,
											RangeTblEntry *rte);
static List *ekorreImportForeignSchema(ImportForeignSchemaStmt *stmt,
									   Oid serveroid);

/*-------------------------------------------------------------------------
 * Implementation of FDW API
 *------------------------------------------------------------------------
 */

/*
 * ekorre_handler
 *
 * Return pointers to ekorre callbacks implementing the FDW API.
 */
Datum
ekorre_handler(PG_FUNCTION_ARGS)
{
	FdwRoutine *fdwroutine = makeNode(FdwRoutine);

	fdwroutine->GetForeignRelSize = ekorreGetRelSize;
	fdwroutine->GetForeignPaths = ekorreGetForeignPaths;
	fdwroutine->GetForeignPlan = ekorreGetForeignPlan;
	fdwroutine->ExplainForeignScan = ekorreExplainForeignScan;
	fdwroutine->BeginForeignScan = ekorreBeginForeignScan;
	fdwroutine->IterateForeignScan = ekorreIterateForeignScan;
	fdwroutine->ReScanForeignScan = ekorreReScanForeignScan;
	fdwroutine->EndForeignScan = ekorreEndForeignScan;
	fdwroutine->AnalyzeForeignTable = ekorreAnalyzeForeignTable;
	fdwroutine->IsForeignScanParallelSafe = ekorreIsForeignScanParallelSafe;

	fdwroutine->ImportForeignSchema = ekorreImportForeignSchema;

	PG_RETURN_POINTER(fdwroutine);
}

/*
 * ekorre_validator
 *
 * Validate the options given by the user to ensure options are syntactically
 * and semantically correct.
 */
Datum
ekorre_validator(PG_FUNCTION_ARGS)
{
	List	   *options;
	Oid			catalog;
	ListCell   *cell;
	char	   *repopath = NULL;
	const struct EkorreOption *option;
	int			stat;

	options = untransformRelOptions(PG_GETARG_DATUM(0));
	catalog = PG_GETARG_OID(1);

	foreach(cell, options)
	{
		DefElem *def = (DefElem *) lfirst(cell);
		bool	found = false;

		for (option = valid_options; option->name; option++)
		{
			if (catalog == option->context &&
				strcmp(option->name, def->defname) == 0)
			{
				found = true;
				break;
			}
		}

		if (!found)
		{
			ereport(ERROR,
					errcode(ERRCODE_FDW_INVALID_OPTION_NAME),
					errmsg("invalid option \"%s\"", def->defname));
		}

		if (strcmp(def->defname, "repopath") == 0)
		{
			if (repopath != NULL)
			{
				ereport(ERROR,
						errcode(ERRCODE_SYNTAX_ERROR),
						errmsg("conflicting or redundant option %s",
							   repopath));
			}

			repopath = defGetString(def);

			/*
			 * Check that the repopath does contain a Git repository before
			 * accepting it to (as much as possible) keep actions on the repo
			 * from failing on incorrect paths.
			 */
			git_libgit2_init();
			stat = git_repository_open_ext(NULL, repopath, GIT_REPOSITORY_OPEN_NO_SEARCH, NULL);
			git_libgit2_shutdown();

			if (stat != 0)
			{
				ereport(ERROR,
						errcode_for_file_access(),
						errmsg("no repository found in repopath: \"%s\"",
							   repopath));
			}
		}
	}

	if (catalog == ForeignTableRelationId && repopath == NULL)
		ereport(ERROR,
				errcode(ERRCODE_FDW_DYNAMIC_PARAMETER_VALUE_NEEDED),
				errmsg("path to repository required"));

	PG_RETURN_VOID();
}

/*
 * ekorreGetRelSize
 * 
 * Estimate the size of the repository.
 */
static void
ekorreGetRelSize(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid)
{
	EkorrePlanState *epstate;
	int				ret;
	git_repository *repository;
	git_revwalk	   *revwalker;
	git_oid			oid;

	/*
	 * Create our planstate and save it in the fdw_private member of the
	 * RelOptInfo such that we can pull it out when generating Paths.
	 */
	epstate = (EkorrePlanState *) palloc0(sizeof(EkorrePlanState));
	epstate->restrictquals = NIL;
	baserel->fdw_private = (void *) epstate;

	get_options(foreigntableid, &epstate->repopath);

	git_libgit2_init();

	ret = git_repository_open(&repository, epstate->repopath);
	if (ret != GIT_OK)
	{
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("unable to open repository: %s",
						git_errmsg()));
	}

	/*
	 * Skip reading the repository if it can be expected to be empty and exit
	 * on a fast path. The ncommits member is already initialized to zero via
	 * the palloc0 call.
	 */
	if (git_repository_is_empty(repository))
		goto report_ncommits;

	/*
	 * The repository contains revisions, walk it and count the number of
	 * objects. We skip looking up the individual commits for now to shave
	 * time from this step.
	 */
	git_revwalk_new(&revwalker, repository);
	git_revwalk_push_head(revwalker);

	while (git_revwalk_next(&oid, revwalker) != GIT_ITEROVER)
		epstate->ncommits++;

	git_revwalk_free(revwalker);

report_ncommits:
	git_repository_free(repository);
	baserel->rows = epstate->ncommits;

	return;
}

/*
 * ekorreGetForeignPaths
 *
 * Generate Paths for scanning the Git repository. As of now a single Path will
 * be returned since there is no support for pushing down quals. A TODO is to
 * generate a Path per revwalker sorting to allow optimized scans wrt ordering.
 */
static void
ekorreGetForeignPaths(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid)
{
	EkorrePlanState *epstate;
	Cost		startup_cost;
	Cost		total_cost;
	Bitmapset  *attrs = NULL;
	int			attindex;
	Relation	rel;
	TupleDesc	tupleDesc;

	epstate = (EkorrePlanState *) baserel->fdw_private;

	if (baserel->baserestrictinfo != NIL)
	{
		ListCell *lc;

		/* Extract all attributes needed to project the results */
		pull_varattnos((Node *) baserel->reltarget->exprs, baserel->relid, &attrs);

		/*
		 * Extract all attributes from restrictions quals and deparse the
		 * expression clauses so we can restrict our scan on the Git repo.
		 */
		foreach(lc, baserel->baserestrictinfo)
		{
			EkorreQualInfo *qual = NULL;
			RestrictInfo   *ri = (RestrictInfo *) lfirst(lc);

			pull_varattnos((Node *) ri->clause, baserel->relid, &attrs);
			ekr_deparse_qual((Expr *) ri->clause, &qual);

			/*
			 * If restriction clause corresponds to a qual we can push down
			 * to the Git repository scan then save it in the planstate for
			 * when we execute the scan.
			 */
			if (qual != NULL)
				epstate->restrictquals = lappend(epstate->restrictquals, qual);
		}

		rel = table_open(foreigntableid, AccessShareLock);
		tupleDesc = RelationGetDescr(rel);
		attindex = -1;

		while ((attindex = bms_next_member(attrs, attindex)) >= 0)
		{
			AttrNumber attnum = attindex + FirstLowInvalidHeapAttributeNumber;
			Form_pg_attribute attr;

			/* Whole row */
			if (attnum == 0)
				break;

			/* System attributes */
			if (attnum < 0)
				continue;

			attr = TupleDescAttr(tupleDesc, attnum - 1);
		}

		table_close(rel, AccessShareLock);
	}

	/*
	 * The costs carry very little meaning since there is only one Path for
	 * accessing the repo, but they required. We guess that the twice the
	 * cpu_tuple_cost accounts for extracting the commit from the revwalker.
	 */
	startup_cost = baserel->baserestrictcost.startup;
	total_cost = startup_cost + (epstate->ncommits * cpu_tuple_cost * 2);

	add_path(baserel, (Path *)
			 create_foreignscan_path(root, baserel,
			 						 NULL,	/* default_pathtarget */
									 baserel->rows,
									 0,		/* disabled_npdes */
									 startup_cost,
									 total_cost,
									 NIL,	/* pathkeys */
									 baserel->lateral_relids,
									 NULL,	/* no extra plan */
									 NIL,	/* fdw_restrictinfo list */
									 NIL));	/* conversion options */
}

/*
 * ekorre_BeginForeignScan
 *
 * Set up state for walking the Git repo.
 */
static void
ekorreBeginForeignScan(ForeignScanState *node, int eflags)
{
	/* ForeignScan *plan = (ForeignScan *) node->ss.ps.plan; */
	EkorreExecutionState *eestate;
	int			ret;

	/*
	 * If the user executes an EXPLAIN query, for now we do nothing. TODO: do
	 * something more interesting here.
	 */
	if (eflags & EXEC_FLAG_EXPLAIN_ONLY)
		return;

	/* Initialize libgit2 global state */
	git_libgit2_init();

	/*
	 * Initialize local state and set all user defined options in the state
	 * object.
	 */
	eestate = (EkorreExecutionState *) palloc0(sizeof(EkorreExecutionState));
	get_options(RelationGetRelid(node->ss.ss_currentRelation), &eestate->repopath);

	/*
	 * Save our local state for when we are called back.
	 */
	node->fdw_state = (void *) eestate;

	/*
	 * The validator has checked that the repo exists so ideally this should
	 * not error out but we check it regardless.
	 */
	ret = git_repository_open(&eestate->repo, eestate->repopath);
	if (ret != GIT_OK)
		ereport(ERROR,
				errcode(ERRCODE_FDW_ERROR),
				errmsg("unable to open Git repository: %s", git_errmsg()));

	ret = git_revwalk_new(&(eestate->revwalker), eestate->repo);
	if (ret != GIT_OK)
		ereport(ERROR,
				errcode(ERRCODE_FDW_ERROR),
				errmsg("unable to read Git revision history: %s",
					   git_errmsg()));

	git_revwalk_push_head(eestate->revwalker);
}

static TupleTableSlot *
ekorreIterateForeignScan(ForeignScanState *node)
{
	EkorreExecutionState *eestate = (EkorreExecutionState *) node->fdw_state;
	TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;
	git_oid			oid;
	git_commit	   *commit;
	const git_signature *commit_author;
	const git_signature *commit_committer;
	char		   *commit_id;

	ExecClearTuple(slot);

	/*
	 * Fetch the next object from the revwalker, and if none are available
	 * return NULL to end the foreign scan.
	 */
	if (git_revwalk_next(&oid, eestate->revwalker) != GIT_OK)
	{
		elog(NOTICE, "revwalk_next failed");
		git_revwalk_free(eestate->revwalker);
		eestate->revwalker = NULL;
		return NULL;
	}

	if (git_commit_lookup(&commit, eestate->repo, &oid) != GIT_OK)
	{
		git_revwalk_free(eestate->revwalker);
		ereport(ERROR,
				errmsg("unable read commit from Git repository: %s",
					   git_errmsg()));
	}

	commit_id = palloc(PG_SHA256_BLOCK_LENGTH + 1);
	memset(commit_id, '\0', PG_SHA256_BLOCK_LENGTH + 1);
	git_oid_fmt(commit_id, git_commit_id(commit));

	commit_author = git_commit_author(commit);
	commit_committer = git_commit_committer(commit);

	/*
	 * We have a revision to show.
	 */
	memset(slot->tts_isnull, false, slot->tts_tupleDescriptor->natts * sizeof(bool));

	/*
	 * Diffstats are only supported if the commit has a parent, for the first
	 * commit in a tree there is nothing to diff against. TODO: implement diffs
	 * against the empty commit, which is different depending on if the repo
	 * use sha1 or sha256 commit oids.
	 */
	if (git_commit_parentcount(commit) > 0)
	{
		git_commit  *parent;
		git_tree	*commit_tree;
		git_tree	*parent_tree;
		git_diff	*diff;
		git_diff_stats *diffstats;

		git_commit_parent(&parent, commit, 0);

		git_commit_tree(&parent_tree, parent);
		git_commit_tree(&commit_tree, commit);

		git_diff_tree_to_tree(&diff, eestate->repo, parent_tree, commit_tree, NULL);

		git_diff_get_stats(&diffstats, diff);

		slot->tts_values[Anum_git_log_deltas] = git_diff_num_deltas(diff);
		slot->tts_values[Anum_git_log_insertions] = git_diff_stats_insertions(diffstats);
		slot->tts_values[Anum_git_log_deletions] = git_diff_stats_deletions(diffstats);
		slot->tts_values[Anum_git_log_changed_files] = git_diff_stats_files_changed(diffstats);

		git_diff_stats_free(diffstats);
		git_diff_free(diff);

		git_commit_free(parent);
		git_tree_free(commit_tree);
		git_tree_free(parent_tree);
	}
	else
	{
		slot->tts_isnull[Anum_git_log_deltas] = true;
		slot->tts_isnull[Anum_git_log_insertions] = true;
		slot->tts_isnull[Anum_git_log_deletions] = true;
		slot->tts_isnull[Anum_git_log_changed_files] = true;
	}

	slot->tts_values[Anum_git_log_commit_id] = PointerGetDatum(cstring_to_text(commit_id));
	/* Author */
	slot->tts_values[Anum_git_log_author_name] = PointerGetDatum(cstring_to_text(commit_author->name));
	slot->tts_values[Anum_git_log_author_email] = PointerGetDatum(cstring_to_text(commit_author->email));
	slot->tts_values[Anum_git_log_author_date] = PG_DATE(commit_author->when.time);
	/* Committer */
	slot->tts_values[Anum_git_log_committer_name] = PointerGetDatum(cstring_to_text(commit_committer->name));
	slot->tts_values[Anum_git_log_committer_email] = PointerGetDatum(cstring_to_text(commit_committer->email));
	slot->tts_values[Anum_git_log_committer_date] = PG_DATE(commit_committer->when.time);

	slot->tts_values[Anum_git_log_summary] = PointerGetDatum(cstring_to_text(git_commit_summary(commit)));
	slot->tts_values[Anum_git_log_message] = PointerGetDatum(cstring_to_text(git_commit_message(commit)));

	ExecStoreVirtualTuple(slot);

	git_commit_free(commit);

	return slot;
}

static void
ekorreReScanForeignScan(ForeignScanState *node)
{
}

/*
 * ekorreEndForeignScan
 *
 * Close down opened resources and finish the operation on the repo.
 */
static void
ekorreEndForeignScan(ForeignScanState *node)
{
	EkorreExecutionState *eestate = (EkorreExecutionState *) node->fdw_state;

	if (!eestate)
		return;

	/* Close the repository */
	if (eestate->repo)
		git_repository_free(eestate->repo);

	/* Shut down libgit2 global state */
	git_libgit2_shutdown();
}

static ForeignScan *
ekorreGetForeignPlan(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid,
					 ForeignPath *best_path, List *tlist, List *scan_clauses,
					 Plan *outer_plan)
{
	Index			scan_relid = baserel->relid;
	ForeignScan		*scan;

	best_path->fdw_private = baserel->fdw_private;

	scan_clauses = extract_actual_clauses(scan_clauses, false);
	scan = make_foreignscan(tlist, scan_clauses, scan_relid, NIL,
							best_path->fdw_private, NIL, NIL, outer_plan);

	return scan;
}

static void
ekorreExplainForeignScan(ForeignScanState *node, ExplainState *es)
{
}

static bool
ekorreAnalyzeForeignTable(Relation relation, AcquireSampleRowsFunc *func,
						  BlockNumber *totalpages)
{
	return false;
}

static bool
ekorreIsForeignScanParallelSafe(PlannerInfo *root, RelOptInfo *rel,
								RangeTblEntry *rte)
{
	/* TODO */
	return false;
}

static List *
ekorreImportForeignSchema(ImportForeignSchemaStmt *stmt, Oid serveroid)
{
	StringInfoData	create_stmt;
	List		   *create_commands = NIL;
	ListCell	   *lc;
	char		   *repopath;

	/*
	 * As of now only the commit log is supported, a TODO is to support more
	 * Git commands as remote schemas.
	 */
	if (strcmp(stmt->remote_schema, "git") != 0)
	{
		ereport(ERROR,
				errcode(ERRCODE_FDW_SCHEMA_NOT_FOUND),
				errmsg("invalid remote schema"),
				errhint("Supported remote schema is: \"git\"."));
	}

	/*
	 * Extract and parse all the IMPORT FOREIGN SCHEMA options for the remote
	 * table, we need a repopath in order to connect to a repo.
	 */
	foreach(lc, stmt->options)
	{
		DefElem		*defelem = (DefElem *) lfirst(lc);

		if (strcmp(defelem->defname, "repopath") == 0)
			repopath = defGetString(defelem);
		else
			ereport(ERROR,
					errcode(ERRCODE_FDW_INVALID_OPTION_NAME),
					errmsg("invalid option \"%s\" in statement",
						   defelem->defname));
	}

	if (repopath == NULL)
	{
		ereport(ERROR,
				errcode(ERRCODE_FDW_OPTION_NAME_NOT_FOUND),
				errmsg("path to repository missing in statement"));
	}

	initStringInfo(&create_stmt);

	/* git log */
	appendStringInfo(&create_stmt,
					 "CREATE FOREIGN TABLE %s.git_log ("
					 "commit_id text, "
					 "author_name text, "
					 "author_email text, "
					 "author_date timestamp with time zone, "
					 "committer_name text, "
					 "committer_email text, "
					 "commit_date timestamp with time zone, "
					 "summary text, "
					 "message text, "
					 "deltas int, "
					 "insertions int, "
					 "deletions int, "
					 "changed_files int"
					 ") SERVER %s "
					 "OPTIONS (repopath '%s')",
					 stmt->local_schema,
					 quote_identifier(stmt->server_name),
					 repopath
					 );

	create_commands = lappend(create_commands, pstrdup(create_stmt.data));

	return create_commands;
}

/*-------------------------------------------------------------------------
 * Internal functions
 *------------------------------------------------------------------------
 */

static void
get_options(Oid foreignTableId, char **repopath)
{
	ForeignTable *table;
	ForeignServer *server;
	ForeignDataWrapper *fdw;
	List	   *options = NIL;
	ListCell   *lc;

	table = GetForeignTable(foreignTableId);
	server = GetForeignServer(table->serverid);
	fdw = GetForeignDataWrapper(server->fdwid);

	options = list_concat(options, fdw->options);
	options = list_concat(options, server->options);
	options = list_concat(options, table->options);

	/*
	 * Clear all options to ensure we return a known result even if the list
	 * of options is empty.
	 */
	*repopath = NULL;

	foreach(lc, options)
	{
		DefElem	   *defelem = (DefElem *) lfirst(lc);

		if (strcmp(defelem->defname, "repopath") == 0)
		{
			*repopath = defGetString(defelem);
			options = foreach_delete_current(options, lc);
			break;
		}

		/* TODO: check for additional required options */
	}
}

/*
 * git_errmsg
 *
 * Return an error message from libgit2, or a boilerplate unknown error in
 * case no string was returned.
 */
static char *
git_errmsg(void)
{
	const git_error *error;

	error = git_error_last();
	if (!error)
		return pstrdup("unknown Git error");

	return error->message;
}

/*
 * ekr_deparse_qual
 *
 * Deparse the qual expression and extract the columns used in it.
 */
static void
ekr_deparse_qual(Expr *node, EkorreQualInfo **qual)
{
	if (node == NULL)
		return;

	switch (nodeTag(node))
	{
		case T_Var:
			ekr_deparse_var((Var *) node, qual);
			break;

		case T_OpExpr:
			ekr_deparse_opexpr((OpExpr *) node, qual);
			break;

		case T_Const:
			ekr_deparse_const((Const *) node, qual);
			break;

		default:
			elog(WARNING, "ekorre: ekr_deparse_qual: unhandled node type");
			break;
	}
}

static void
ekr_deparse_var(Var *node, EkorreQualInfo **qual)
{
	if (!*qual)
		return;

	(*qual)->varattno = node->varattno;
}

static void
ekr_deparse_const(Const *node, EkorreQualInfo **qual)
{
	/* NULL value */
	if (node->constisnull)
	{
		/*
		 * TODO: NULL really doesn't make much sense unless the expression is
		 * '!= NULL', so at least handle that case.
		 */
		return;
	}

	switch (node->consttype)
	{
		/* Integer Const values. To keep things simple we only store int64s */
		case INT2OID:
			(*qual)->constval_int = (int64) DatumGetInt16(node->constvalue);
			break;
		case INT4OID:
			(*qual)->constval_int = (int64) DatumGetInt32(node->constvalue);
			break;
		case INT8OID:
			(*qual)->constval_int = DatumGetInt64(node->constvalue);
			break;

		/* String values */
		case BPCHAROID:
		case VARCHAROID:
		case TEXTOID:
			{
				char   *string;
				Oid		stringfunc;
				bool	varlen;

				getTypeOutputInfo(TEXTOID, &stringfunc, &varlen);
				string = OidOutputFunctionCall(stringfunc, node->constvalue);
				(*qual)->constval_string = pstrdup(string);
			}
			break;

		/* Date values */
		case DATEOID:
			(*qual)->constval_ts = DatumGetTimestamp(DirectFunctionCall1(date_timestamp,
																	   node->constvalue));
			break;
		case TIMESTAMPOID:
		case TIMESTAMPTZOID:
			(*qual)->constval_ts = DatumGetTimestamp(node->constvalue);
			break;

		default:
				elog(WARNING, "ekorre: ekr_deparse_const: unhandled Const value");
				break;
	}
}

static void
ekr_deparse_opexpr(OpExpr *node, EkorreQualInfo **qual)
{
	HeapTuple			tuple;
	Form_pg_operator	pgopform;
	ListCell		   *arg;
	QualOp				op = OP_UNSUPPORTED;

	tuple = SearchSysCache1(OPEROID, ObjectIdGetDatum(node->opno));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for operator %u", node->opno);

	pgopform = (Form_pg_operator) GETSTRUCT(tuple);

	/* Only infix operators are supported */
	if (pgopform->oprkind == 'b')
	{
		const char *opname = get_opname(node->opno);

		if (opname[0] == '=')
			op = OP_EQ;
		else if (opname[0] == '<')
		{
			if (!opname[1])
				op = OP_LT;
			else if (opname[1] == '=')
				op = OP_LE;
		}
		else if (opname[0] == '>')
		{
			if (!opname[1])
				op = OP_GT;
			else if (opname[1] == '=')
				op = OP_GE;
		}

		/*
		 * If we have come across an operator which we can't push down then
		 * exit and leave the expression to the postgres executor.
		 */
		if (op == OP_UNSUPPORTED)
		{
			ReleaseSysCache(tuple);
			return;
		}

		*qual = palloc(sizeof(EkorreQualInfo));
		(*qual)->op = op;

		/* Deparse left operand */
		arg = list_head(node->args);
		ekr_deparse_qual(lfirst(arg), qual);
		/* Deparse right operand */
		arg = list_tail(node->args);
		ekr_deparse_qual(lfirst(arg), qual);
	}

	ReleaseSysCache(tuple);
}
