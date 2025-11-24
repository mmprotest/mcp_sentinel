import pytest

from mcp_sentinel.runtime.secure_http import SecureHTTPClient
from mcp_sentinel.runtime.secure_fs import SecureFS
from mcp_sentinel.runtime import UnauthorizedDomainError, FilesystemAccessError


def test_secure_http_blocks_disallowed():
    client = SecureHTTPClient(["example.com"])
    with pytest.raises(UnauthorizedDomainError):
        client.get("https://evil.com")


def test_secure_fs_modes(tmp_path):
    fs = SecureFS(mode="none")
    with pytest.raises(FilesystemAccessError):
        fs.open(tmp_path / "file.txt", "w")

    fs_ro = SecureFS(mode="read_only")
    with pytest.raises(FilesystemAccessError):
        fs_ro.open(tmp_path / "file.txt", "w")

    fs_rw = SecureFS(mode="read_write")
    handle = fs_rw.open(tmp_path / "file.txt", "w")
    handle.write("ok")
    handle.close()
    assert (tmp_path / "file.txt").exists()
