Tests
=====

Various ways to test PgBouncer:

- `test_xxx.py`

    General test of basic functionality and different configuration
    parameters including timeouts, pool size, online restart,
    pause/resume, etc.

    To be able to run these tests you need to install a few python test
    libraries.  To do so, you should run the following from of the root of the
    repository:

    pip3 install --user -r requirements.txt

    To run the tests after doing that, just run `pytest -n auto` from the root
    of the repository.  This needs PostgreSQL server programs (`initdb`,
    `pg_ctl`) in the path, so if you are on a system that doesn't have those in
    the normal path (e.g., Debian, Ubuntu), set `PATH` beforehand.

    Optionally, this test suite can use `iptables`/`pfctl` to simulate
    various network conditions.  To include these tests, set the
    environment variable USE_SUDO to a nonempty value, for example
    `make check USE_SUDO=1`.  This will ask for sudo access, so it
    might convenient to run `sudo -v` before the test, or set up
    `/etc/sudoers` appropriately at your peril.  Check the source if
    there are any doubts.

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


- `hba_test`

    Tests hba parsing.  Run `make all` to build and `./hba_test` to execute.

    This test is run by `make check`.

- `run-conntest.sh`

    This is a more complex setup that continuously runs queries
    through PgBouncer while messing around with the network, checking
    whether PgBouncer correctly reconnects and all the queries get
    processed.  First, run `make asynctest` to build, then see
    `run-conntest.sh` how to run the different pieces.

- `stress.py`

    Stress test, see source for details.  Requires Python and `psycopg2` module.
