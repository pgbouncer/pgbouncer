# Copyright 2015-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Amazon Software License (the "License").
# You may not use this file except in compliance with the License. A copy of the License is located at
#
#     http://aws.amazon.com/asl/
#
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
# See the License for the specific language governing permissions and limitations under the License.

# Python module containing example query routing table function.
# Configure path/name to this file in [pgbouncer] section of ini file.
# Ex:
#    routing_rules_py_module_file = /etc/pgbouncer/routing_rules.py


# ROUTING TABLE
# ensure all dbkey values are defined in [database] section of the pgbouncer ini file


# ROUTING FN - CALLED FROM PGBOUNCER-RR - DO NOT CHANGE NAME
# IMPLEMENTS REGEX RULES DEFINED IN ROUTINGTABLE OBJECT
# RETURNS FIRST MATCH FOUND
def routing_rules(username, query, in_transaction):
	if "ipo" in query:
		return "global_db"
	return None

if __name__ == "__main__":
    print ("test for tablea:" + routing_rules("master", "select * from tablea;"))
    print ("test for tableb:" + routing_rules("master", "select * from tableb;"))
