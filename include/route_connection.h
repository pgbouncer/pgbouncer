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

PgSchema* find_schema_to_cluster_mapping(PgSocket *client, char *schema_name);
char* get_database_cluster_key(PgSocket *client, char* schema_name, char* query_str);
bool route_client_connection (PgSocket *client, char *schema, PktHdr *pkt);


