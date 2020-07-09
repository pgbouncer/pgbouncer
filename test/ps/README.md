# Prepared Statement tests

This directory contains specialized tests for the `prepared_statement_lock` configuration option.

## How to run the Go tests

Install Go (version 1.13 or later)

1. `cd pgbouncer`
3. `test/ps/run-docker-testdb.sh` (in it's own console)
4. `make -j && ./pgbouncer test/ps/test.ini` (in it's own console)
5. `go run test/ps/test.go`