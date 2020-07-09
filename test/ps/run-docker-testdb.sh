#!/bin/sh

docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=kama postgres:12