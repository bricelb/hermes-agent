"""Permission hardening must preserve live SQLite locks and reject symlinks."""

import errno
import os
import stat
import subprocess
import sys

import pytest

from hermes_state import SessionDB, _secure_state_db_files
from hermes_state_dbfile import iter_deleted_sqlite_sidecar_holders


@pytest.mark.linux_only
def test_hardening_preserves_live_wal_generation_across_other_openers(tmp_path):
    path = tmp_path / "state.db"
    first = SessionDB(path)
    second = SessionDB(path)
    try:
        for _ in range(3):
            _secure_state_db_files(path, create_main=True)
            subprocess.run(
                [sys.executable, "-c",
                 "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); "
                 "c.execute('SELECT count(*) FROM sessions').fetchone(); c.close()",
                 str(path)],
                check=True, capture_output=True, text=True, timeout=10,
            )
            assert iter_deleted_sqlite_sidecar_holders(path) == []
            first._raise_if_db_replaced()
            first._conn.execute("BEGIN IMMEDIATE")
            first._conn.rollback()
    finally:
        second.close()
        first.close()
    assert iter_deleted_sqlite_sidecar_holders(path) == []
    reopened = SessionDB(path)
    reopened.close()


@pytest.mark.linux_only
@pytest.mark.parametrize("suffix", ["", "-wal", "-shm"])
def test_hardening_keeps_files_private_and_refuses_symlink_targets(tmp_path, suffix):
    path = tmp_path / "state.db"
    old_umask = os.umask(0)
    try:
        _secure_state_db_files(path, create_main=True)
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    sidecar = path.with_name(path.name + suffix)
    if sidecar.exists():
        sidecar.unlink()
    target = tmp_path / "unrelated-file"
    target.write_text("keep this private test content unchanged")
    target.chmod(0o644)
    sidecar.symlink_to(target)
    with pytest.raises(OSError) as error:
        _secure_state_db_files(path, create_main=True)
    assert error.value.errno == errno.ELOOP
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert target.read_text() == "keep this private test content unchanged"
