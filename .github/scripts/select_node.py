"""Select a verified Node.js distribution for the Linux x64 compatibility matrix."""

import hashlib
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
from urllib.request import urlopen

# To update a lane, verify SHASUMS256.txt.sig with the Node.js release keyring.
# Take the xz digest from the signed list, verify and unpack that archive, then
# compute runtime_hash() on its installation prefix for the runner-cache check.
RELEASES = {
    "18": (
        "18.20.8",
        "5467ee62d6af1411d46b6a10e3fb5cacc92734dbcef465fea14e7b90993001c9",
        "74c02be9f54c417d3d719a384f268cb43f42433dc0248d993cdc9a455b5bd7dd",
    ),
    "20": (
        "20.20.2",
        "df770b2a6f130ed8627c9782c988fda9669fa23898329a61a871e32f965e007d",
        "1a23963230efe4d15e142c3237975f0f7cd674d44a4458626552dc96edde1a97",
    ),
    "22": (
        "22.23.5",
        "cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8",
        "110c92aa53c06cba7c44dabe45f277c8131cfc26256a3e7b011d2157d6b016db",
    ),
    "24": (
        "24.22.3",
        "4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb",
        "0abe00407b77cfed1a36d3295a9baa36030f99e62cd2b2d43ae28f349b2e42e8",
    ),
}


def file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def runtime_hash(prefix):
    npm = prefix / "lib/node_modules/npm"
    if (prefix / "bin/npm").resolve() != (npm / "bin/npm-cli.js").resolve():
        raise ValueError("Unexpected npm entry point")
    result = hashlib.sha256()
    for path in [prefix / "bin/node", *sorted(npm.rglob("*"))]:
        if path.is_symlink():
            value = "link:" + os.readlink(path)
        elif path.is_file():
            value = file_hash(path)
        elif path.is_dir():
            continue
        else:
            raise ValueError(f"Unexpected runtime file {path}")
        result.update(f"{path.relative_to(prefix).as_posix()}\0{value}\n".encode())
    return result.hexdigest()


def install(version, expected_hash, destination):
    name = f"node-v{version}-linux-x64"
    url = f"https://nodejs.org/dist/v{version}/{name}.tar.xz"
    with tempfile.TemporaryFile() as archive:
        with urlopen(url, timeout=45) as response:
            shutil.copyfileobj(response, archive)
        size = archive.tell()
        archive.seek(0)
        if hashlib.file_digest(archive, "sha256").hexdigest() != expected_hash:
            raise ValueError(f"Archive digest mismatch for {name}")
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r:xz") as contents:
            contents.extractall(destination, filter="data")
    print(f"Verified {url} ({size} bytes)")
    return destination / name


def main(major):
    if (os.environ["RUNNER_OS"], os.environ["RUNNER_ARCH"]) != ("Linux", "X64"):
        raise ValueError("Node release pins require a Linux x64 runner")
    version, archive_hash, expected_runtime = RELEASES[major]
    prefix = Path(os.environ["RUNNER_TOOL_CACHE"]) / "node" / version / "x64"
    if prefix.with_suffix(".complete").is_file() and prefix.is_dir():
        if runtime_hash(prefix) != expected_runtime:
            raise ValueError(f"Runner Node or npm differs from verified release {version}")
        print(f"Verified runner installation {prefix} (0 runtime download bytes)")
    else:
        destination = Path(tempfile.mkdtemp(prefix="node-", dir=os.environ["RUNNER_TEMP"]))
        prefix = install(version, archive_hash, destination)
    with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as output:
        print(prefix / "bin", file=output)
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
        print(f"OTP_NODE_BIN={prefix / 'bin'}", file=output)


if __name__ == "__main__":
    main(sys.argv[1])
