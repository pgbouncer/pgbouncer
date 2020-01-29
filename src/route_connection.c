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

#include "bouncer.h"
#include <usual/pgutil.h>
#include <libpq-fe.h>
#include <string.h>


static void
get_app_tenant_service(PgSocket *client, char *schema, char *app, char *tenant, char *service_name){
    /*
    Splits str in schema_name by '_' and returns the app, tenant and service names in the string.
    Considers first two strings delimited by '_' as app, tenant respectively, everything that follows as service_name
    Ex: - get_app_tenant_svc_names('mc_tenant_artifact') returns ('mc', 'tenant', 'artifact')
        - get_app_tenant_svc_names('mc_tenant_artifact_info_name_extra') returns ('mc', 'tenant', 'artifact_info_name_extra')
    :param schema_name: name of the schema
    :return: app, tenant and schema names
    */
    char *token;
    if (schema == NULL || client == NULL){
        return;
    }
    token = strtok(schema, "_");
    // loop through the string to extract all other tokens
    if (token == NULL ) {
         slog_error(client, "App name parsing failed.");
        return;
    }
    strcpy(app, token);
    token = strtok(NULL, "_");
    if (token == NULL ) {
        slog_error(client, "Tenant name parsing failed.");
        return;
    }
    strcpy(tenant, token);
    token = strtok(NULL, " ");
    if (token == NULL ) {
        slog_error(client, "Service name parsing failed.");
        return;
    }
    strcpy(service_name, token);
    slog_error(client, "App: %s, tenant: %s and service name: %s.", app, tenant, service_name);
    return;
}

PgSchema* find_schema_to_cluster_mapping(PgSocket *client, char *schema_name){
    PGconn     *conn;
    PGresult   *res = NULL;

    char *pg_host = getenv("PG_HOST_WRITE");
    char *pg_port = getenv("PG_PORT");
    char *pg_db = getenv("PG_DB");
    char *pg_user = getenv("PG_USER");
    char *pg_pwd = getenv("PG_PWD");
    char app_name[64];
    char tenant_name[64];
    char service_name[64];
    int  row, col;
    char *cluster_id = NULL;
    char *cluster_name = NULL;
    char db_key[100];
    PgSchema *schema = NULL;
    const char *cluster_id_query_values[3] = {(char *)&app_name, (char *)&tenant_name,(char *)&service_name};
    char *cluster_id_query = "select cluster_id from tenant_mapping where app_name=$1::varchar and tenant_name=$2::varchar and service_name='$3::varchar";
    char *cluster_name_query = "select cluster_name from cluster_info where id=$1::varchar";
    int nFields = 0;

    if (client == NULL){
		return NULL;
    }

    if (schema_name == NULL){
        slog_error(client, "schema for the query is NULL");
		return NULL;
    }

    get_app_tenant_service(client, schema_name, app_name, tenant_name, service_name);
    conn = PQsetdbLogin(pg_host, pg_port, NULL, NULL, pg_db, pg_user, pg_pwd);

    /* Check to see that the backend connection was successfully made */
    if (PQstatus(conn) != CONNECTION_OK)
    {
        slog_error(client, "Connection to database failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return NULL;
    }

    /*
     * Get the cluster id from the query
     */


    res = PQexecParams(conn, cluster_id_query, 3, NULL, cluster_id_query_values, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK){
        slog_error(client, "select cluster_id failed for schema: %s,  failed: %s", schema_name, PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return NULL;

    }
    nFields = PQnfields(res);
    /* next, print out the rows */
    for (row = 0; row < PQntuples(res); row++){
        for (col = 0; col < nFields; col++) {
             cluster_id = PQgetvalue(res, row, col);
        }
    }
    if (cluster_id == NULL || strlen(cluster_id) == 0) {
        slog_error(client, "cluster id not found for  schema = %s", schema_name);
        PQclear(res);
        PQfinish(conn);
        return NULL;
    }
    slog_debug(client, "cluster id = %s, schema = %s", cluster_id, schema_name);

    PQclear(res);
    /*
     * Get the cluster name from the query
     */
    const char *cluster_name_values[1] = {(char *)cluster_id};
    res = PQexecParams(conn, cluster_name_query, 1, NULL, cluster_name_values, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK){
        slog_error(client, "select cluster_name failed for schema: %s,  failed: %s", schema_name, PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return NULL;

    }
    nFields = PQnfields(res);
    /* next, print out the rows */
    for (row = 0; row < PQntuples(res); row++){
        for (col = 0; col < nFields; col++) {
             cluster_name = PQgetvalue(res, row, col);
        }
    }
    if (cluster_name == NULL || strlen(cluster_name) == 0) {
        slog_error(client, "cluster id not found for  schema = %s", schema_name);
        PQclear(res);
        PQfinish(conn);
        return NULL;
    }
    slog_debug(client, "cluster name = %s, schema = %s", cluster_id, schema_name);


    PQclear(res);
    /* close the connection to the database and cleanup */
    PQfinish(conn);
    strcpy(db_key, cluster_name);
    strcat(db_key, "_");
    strcat(db_key, service_name);
    strcat(db_key, "_");
    strcat(db_key, "db");
    strcat(db_key, ".write");
    schema  = add_schema(schema_name, db_key);
    if (schema == NULL){
        slog_error(client, "schema addition to database failed = %s", schema_name);
        return NULL;
    }
    return schema;

}

/*
 * From the schema name get the cluster tenant key
 */
char* get_database_cluster_key(PgSocket *client, char* schema_name, char* query_str) {

    PgSchema *schema = NULL;
    if (client == NULL) {
		return NULL;
	}
	if (schema == NULL || strlen(schema_name) == 0) {
		slog_error(client, "schema for the query is NULL");
		return NULL;
	}
	if (query_str == NULL) {
		slog_error(client, "Query string is NULL");
		return NULL;
	}
	schema = find_schema(schema_name);
	if (schema == NULL){
	   schema = find_schema_to_cluster_mapping(client, schema_name);
	   if (schema == NULL){
	       slog_error(client, "Cluster mapping for the schema dont exist : %s", schema_name);
	       return NULL;
	   }
	}
	return schema->dbname;
}


/* route_client_connection:
 *  - applied to packets of type 'Q' (Query) and 'P' (Prepare) only
 *  - apply routing rules to query string contained in the buffer, and determine target database
 *  - locate connection pool for target database to client object, and return
 */
bool route_client_connection(PgSocket *client, char* schema, PktHdr *pkt) {
	SBuf *sbuf = &client->sbuf;
	char *pkt_start;
	char *query_str;
	char *dbname = NULL;
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

	slog_debug(client, "route_client_connection: Username => %s", client->auth_user->name);
	slog_debug(client, "route_client_connection: Query => %s", query_str);
	slog_debug(client, "route_client_connection: Packet Type => '%c'", pkt->type);
	if (schema != NULL){
	    slog_debug(client, "RoutingInfo: Schema: %s, Query: %s", schema, query_str);
	} else {
	    slog_debug(client, "RoutingInfo: Schema: public, Query: %s", query_str);
	    return false;
	}

	/*
	if (strcmp(cf_routing_rules_py_module_file, "not_enabled") == 0) {
		slog_debug(client,
				"Query routing not enabled in config (routing_rules_py_module_file)");
		return true;
	}

	dbname = pycall(client, client->auth_user->name, schema, query_str,cf_routing_rules_py_module_file,
			"routing_rules");

    */
    dbname = get_database_cluster_key(client, schema, query_str);


	if (dbname == NULL) {
		slog_debug(client, "routing_rules returned 'None' - existing connection preserved");
		free(dbname);
		return false;
	}

	db = find_database(dbname);
	if (db == NULL) {
		slog_error(client,
				"nonexistant database key <%s> returned by routing_rules",
				dbname);
		slog_error(client, "check ini and/or routing rules function");
		free(dbname);
		return false;
	}
	pool = get_pool(db, client->auth_user);
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
		client->pool = pool;
	} else {
		slog_debug(client, "already connected to pool <%s>", dbname);
	}
	free(dbname);
	return true;
}

