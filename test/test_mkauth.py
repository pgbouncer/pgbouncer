"""
Tests that cover the functionality of etc/mkauth.py
"""

import subprocess
from pathlib import Path

import psycopg
import pytest

from .utils import WINDOWS, run

if WINDOWS:
    pytest.skip(allow_module_level=True)

SCRIPT_PATH = Path().absolute().parent / "etc" / "mkauth.py"


def test_stdout(pg):
    """
    Test that mkauth.py is able to return non zero error code successfully
    """
    result = run(
        f"{SCRIPT_PATH} - 'postgresql://postgres@{pg.host}:{pg.port}/postgres'",
        capture_output=True,
        check=False,
    )
    output = result.stdout.decode().split("\n")
    assert '"bouncer" ""' in output
    assert result.returncode == 0


def test_too_few_args():
    "Test behavior when too few args are passed to etc/mkauth.py script"
    result = run(
        f"{SCRIPT_PATH} -",
        capture_output=True,
        check=False,
    )
    assert result.stdout == b"usage: mkauth DSTFN CONNSTR\n"
    assert result.returncode == 1


def test_too_many_args():
    "Test behavior when too many args are passed to etc/mkauth.py script"
    result = run(
        f"{SCRIPT_PATH} - last_arg extra_arg",
        capture_output=True,
        check=False,
    )
    assert result.stdout == b"usage: mkauth DSTFN CONNSTR\n"
    assert result.returncode == 1


def test_file_already_exists(pg, tmp_path):
    mkauth_output_fp = tmp_path / "mkauth_output.txt"
    mkauth_output_fp.touch()
    result = run(
        f"{SCRIPT_PATH} {mkauth_output_fp.absolute()} 'postgresql://postgres@{pg.host}:{pg.port}/postgres'",
        capture_output=True,
        check=False,
    )
    assert '"bouncer" ""' in mkauth_output_fp.read_text()
    assert result.returncode == 0


def test_file_does_not_exist(pg, tmp_path):
    "Test that etc/mkauth.py script will correctly run and create the output file if it does not exist"
    mkauth_output_fp = tmp_path / "mkauth_output.txt"
    result = run(
        f"{SCRIPT_PATH} {mkauth_output_fp.absolute()} 'postgresql://postgres@{pg.host}:{pg.port}/postgres'",
        capture_output=True,
        check=False,
    )
    assert '"bouncer" ""' in mkauth_output_fp.read_text()
    assert result.returncode == 0
