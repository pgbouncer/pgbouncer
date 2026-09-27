import subprocess
from pathlib import Path

import psycopg
import pytest

from .utils import WINDOWS, run

if WINDOWS:
    pytest.skip(allow_module_level=True)


def test_mkauth_stdout(bouncer):
    """
    Test that mkauth.py is able to return non zero error code successfully
    """
    script_path = Path().absolute().parent / "etc" / "mkauth.py"
    result = run(
        f"{script_path.absolute()} - 'postgresql://postgres@{bouncer.pg.host}:{bouncer.pg.port}/postgres'",
        capture_output=True,
    )
    output = result.stdout.decode().split("\n")
    assert '"bouncer" ""' in output


def test_mkauth_wrong_number_args():
    script_path = Path().absolute().parent / "etc" / "mkauth.py"
    with pytest.raises(subprocess.CalledProcessError):
        run(
            f"{script_path.absolute()} -",
            capture_output=True,
        )


def test_mkauth_file_already_exists(bouncer, tmp_path):
    mkauth_output_fp = tmp_path / "mkauth_output.txt"
    mkauth_output_fp.touch()
    script_path = Path().absolute().parent / "etc" / "mkauth.py"
    run(
        f"{script_path.absolute()} {mkauth_output_fp.absolute()} 'postgresql://postgres@{bouncer.pg.host}:{bouncer.pg.port}/postgres'",
        capture_output=True,
    )
    assert '"bouncer" ""' in mkauth_output_fp.read_text()


def test_mkauth_file_does_not_exist(bouncer, tmp_path):
    mkauth_output_fp = tmp_path / "mkauth_output.txt"
    script_path = Path().absolute().parent / "etc" / "mkauth.py"
    run(
        f"{script_path.absolute()} {mkauth_output_fp.absolute()} 'postgresql://postgres@{bouncer.pg.host}:{bouncer.pg.port}/postgres'",
        capture_output=True,
    )
    assert '"bouncer" ""' in mkauth_output_fp.read_text()
