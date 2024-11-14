/*
Copyright 2015-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). 
You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. 
This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
*/

/*
 * pgbouncer-rr extension: client connection routing - choose target database pool based on rules
 * applied to client query.
 */

#include <Python.h>
#include "bouncer.h"
#include <usual/pgutil.h>

/* private function prototypes */
char *call_python_routing_rules(PgSocket *client, char *query_str, int in_transaction);

/* route_client_connection:
 *  - applied to packets of type 'Q' (Query) and 'P' (Prepare) only
 *  - apply routing rules to query string contained in the buffer, and determine target database
 *  - locate connection pool for target database to client object, and return
 */
bool route_client_connection(PgSocket *client, int in_transaction, PktHdr *pkt) {
	SBuf *sbuf = &client->sbuf;
	char *pkt_start;
	char *query_str;
	char *dbname;
	PgDatabase *db;
	PgPool *pool;

	/* extract query string from packet */
	/* first byte is the packet type (which we already know)
	 * next 4 bytes is the packet length
	 * For packet type 'Q', the query string is next
	 * 	'Q' | int32 len | str query
	 * For packet type 'P', the query string is after the stmt string
	 * 	'P' | int32 len | str stmt | str query | int16 numparams | int32 paramoid
	 * (Ref: https://www.pgcon.org/2014/schedule/attachments/330_postgres-for-the-wire.pdf)
	 */

	pkt_start = (char *) &sbuf->io->buf[sbuf->io->parse_pos];
	/* printHex(pkt_start, pkt->len); */

	if (pkt->type == 'Q') {
		query_str = (char *) pkt_start + 5;
	} else if (pkt->type == 'P') {
		char *stmt_str = pkt_start + 5;
		query_str = stmt_str + strlen(stmt_str) + 1;
	} else {
		fatal("Invalid packet type - expected Q or P, got %c", pkt->type);
	}

	slog_debug(client, "route_client_connection: Username => %s", client->login_user->name);
	slog_debug(client, "route_client_connection: Query => %s", query_str);

	if (strcmp(cf_routing_rules_py_module_file, "not_enabled") == 0) {
		slog_debug(client,
				"Query routing not enabled in config (routing_rules_py_module_file)");
		return true;
	}

	dbname = pycall(client, client->login_user->name, query_str, in_transaction, cf_routing_rules_py_module_file,
			"routing_rules");
	if (dbname == NULL) {
		slog_debug(client, "routing_rules returned 'None' - existing connection preserved");
		return false;
	}

	db = find_database(dbname);
	if (db == NULL) {
		slog_error(client,
				"nonexistent database key <%s> returned by routing_rules",
				dbname);
		slog_error(client, "check ini and/or routing rules function");
		free(dbname);
		return false;
	}
	pool = get_pool(db, client->login_user);
	if (client->pool != pool) {
		if (client->link != NULL) {
			/* release existing server connection back to pool */
			slog_debug(client, "releasing existing server connection");
			release_server(client->link);
			client->link = NULL;
		}
		/* assign client to new pool */
		slog_debug(client,
				"assigning client to connection pool for database <%s>",
				dbname);

                /* Move the client over to the other pool for correct pool stats - needed for pool size maint */
                statlist_remove(&client->pool->active_client_list, &client->head);
                statlist_append(&pool->active_client_list, &client->head);

		client->pool = pool;
	} else {
		slog_debug(client, "already connected to pool <%s>", dbname);
	}
	free(dbname);
	return true;
}

