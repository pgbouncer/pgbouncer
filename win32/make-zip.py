"""Build the Windows binary distribution zip.

Usage: make-zip.py --strip PROG -o OUTPUT.zip FILE...

The files are stored flat under a single top-level directory named
after the archive (minus the .zip suffix).

.exe and .dll inputs are stripped and stored verbatim.  Every other
input is treated as text and is stored with CRLF line endings, so that
the packaged configuration examples and documentation open correctly
in Windows editors.  Note that the state of the files on disk depends
on git core.autocrlf; we need to handle all variants of that.

"""

import argparse
import os
import re
import subprocess
import tempfile
import zipfile

BINARY_SUFFIXES = (".exe", ".dll")

# Any of the three line ending conventions, so the conversion is idempotent.
EOL_RE = re.compile(rb"\r\n|\r|\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strip",
        metavar="PROG",
        required=True,
        help="strip program to run on the binaries",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        metavar="OUTPUT.zip",
        dest="output",
        required=True,
        help="archive to write",
    )
    parser.add_argument("files", metavar="FILE", nargs="+")
    args = parser.parse_args()

    if not args.strip:
        parser.error("--strip needs the name of a strip program")
    if not args.output.endswith(".zip"):
        parser.error(f"output file must end in .zip: {args.output}")
    # The top-level directory inside the archive is named after the archive.
    prefix = os.path.basename(args.output[: -len(".zip")])

    binaries = [f for f in args.files if f.endswith(BINARY_SUFFIXES)]
    texts = [f for f in args.files if not f.endswith(BINARY_SUFFIXES)]

    # Keep the temporary directory next to the output file, so that the
    # final os.replace() stays within one file system.  (On Windows,
    # renaming across drives fails.)
    outdir = os.path.dirname(os.path.abspath(args.output))
    with tempfile.TemporaryDirectory(dir=outdir) as tmpdir:
        tmpzip = os.path.join(tmpdir, "out.zip")
        with zipfile.ZipFile(tmpzip, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in binaries:
                add(zf, prefix, strip(f, args.strip, tmpdir), name=os.path.basename(f))
            for f in texts:
                add(zf, prefix, f, text=True)
        os.replace(tmpzip, args.output)


def strip(path, strip_prog, tmpdir):
    """Return the path of a stripped copy of path, made in tmpdir."""
    stripped = os.path.join(tmpdir, os.path.basename(path))
    subprocess.run([strip_prog, "-o", stripped, path], check=True)
    return stripped


def add(zf, prefix, path, name=None, text=False):
    """Store path in the archive as prefix/name, converting text to CRLF."""
    info = zipfile.ZipInfo.from_file(path, f"{prefix}/{name or os.path.basename(path)}")
    info.compress_type = zipfile.ZIP_DEFLATED
    # Bit 0 of the internal attributes marks an entry as text.
    info.internal_attr = 1 if text else 0
    with open(path, "rb") as f:
        data = f.read()
    if text:
        data = EOL_RE.sub(b"\r\n", data)
    zf.writestr(info, data)


if __name__ == "__main__":
    main()
