import subprocess

from .utils import run


def test_show(bouncer):
    show_items = [
        "clients",
        "config",
        "databases",
        # Calling show fds on MacOS leaks the returned file descriptors to the
        # python test runner. So we don't test this one directly. SHOW FDS is
        # still tested indirectly by the takeover tests.
        # "fds",
        "help",
        "lists",
        "pools",
        "servers",
        "sockets",
        "active_sockets",
        "state",
        "stats",
        "stats_totals",
        "stats_averages",
        "users",
        "totals",
        "mem",
        "dns_hosts",
        "dns_zones",
    ]

    for item in show_items:
        bouncer.admin(f"SHOW {item}")


def test_show_version(bouncer):
    admin_version = bouncer.admin_value(f"SHOW VERSION")
    subprocess_result = run(
        [*bouncer.base_command(), "--version"],
        stdout=subprocess.PIPE,
        shell=False,
        encoding="utf8",
    )
    subprocess_version = subprocess_result.stdout.split("\n")[0]
    assert admin_version == subprocess_version


def test_help(bouncer):
    run([*bouncer.base_command(), "--help"], shell=False)
