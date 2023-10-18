Tests
=====

## Setting up Python dependencies for testing

To be able to run most of the tests you need to install a few python tools.  To
do so, you should run the following from the root of the repository:

```bash
pip3 install --user -r requirements.txt
```

This will install the packages globally on your system, if you don't want to do
that (or if tests are still not working after executing the above command) you can use a
[virtual environment][1] instead:
```bash
# create a virtual environment (only needed once)
python3 -m venv env

# activate the environment. You will need to activate this environment in
# your shell every time you want to run the tests. (so it's needed once per
# shell).
source env/bin/activate

# Install the dependencies (only needed once, or whenever extra dependencies
# get added to requirements.txt)
pip install -r requirements.txt
```

[1]: https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/#creating-a-virtual-environment


## Various ways to test PgBouncer

### `test_xxx.py`

These are general tests of basic functionality and different configuration
parameters including timeouts, pool size, online restart, pause/resume, etc.

You can run these tests using `pytest -n auto` from the root of the repository
(after installing the python dependencies as explained above). This needs
PostgreSQL server programs (`initdb`, `pg_ctl`) in the path, so if you are on a
system that doesn't have those in the normal path (e.g., Debian, Ubuntu), set
`PATH` beforehand.

Optionally, this test suite can use `iptables`/`pfctl` to simulate various
network conditions.  To include these tests, set the environment variable
USE_SUDO to a nonempty value, for example `make check USE_SUDO=1`.  This will
ask for sudo access, so it might convenient to run `sudo -v` before the test, or
set up `/etc/sudoers` appropriately, at your peril.  Check the source if there
are any doubts.

This test is run by `make check`.

You can review the pytest docs on how to run tests with pytest, but the most
common commands that you'll want to use are:

```bash
# Run all tests in parallel
pytest -n auto

# Run all tests sequentially
pytest

# Run a specific test
pytest test/test_limits.py::test_max_user_connections

# Run a specific test file in parallel
pytest -n auto test/test_limits.py

# Run any test that contains a certain string in the name
pytest -k ssl
```


### `hba_test`

Tests hba parsing.  Run `make all` to build and `./hba_test` to execute.

This test is run by `make check`.


### `run-conntest.sh`

This is a more complex setup that continuously runs queries through PgBouncer
while messing around with the network, checking whether PgBouncer correctly
reconnects and all the queries get processed.  First, run `make asynctest`
to build, then see `run-conntest.sh` how to run the different pieces.

### `stress.py`

Stress test, see source code for details.  Requires Python and `psycopg2` module.
