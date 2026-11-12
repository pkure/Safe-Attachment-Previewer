# hal-id: #HAL-20261111-0003-PK-T3
"""The network lock, attacked from inside: every way a hijacked renderer might open a connection must fail."""

import json
import subprocess
import sys

from saferender import lockdown


def run_locked(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", "-c", code], preexec_fn=lockdown.apply, capture_output=True,
                          text=True, timeout=60)


def test_control_sockets_open_without_lock():
    # Negative control: without the lock, creating sockets works (so "blocked" below really is the lock).
    r = subprocess.run([sys.executable, "-I", "-c", "import socket; socket.socket().close(); print('ok')"],
                       capture_output=True, text=True)
    assert r.stdout.strip() == "ok"


def test_verify_reports_locked():
    v = lockdown.verify()
    assert v["verified"], v
    assert v["probe"]["unix"] == "open"


def test_child_processes_inherit_lock():
    # LibreOffice / tesseract / clamscan are child processes: a grandchild must be locked too.
    code = ("import subprocess, sys; print(subprocess.run([sys.executable, '-I', '-c', "
            "'import socket\\ntry:\\n socket.socket(); print(\"open\")\\nexcept OSError as e: print(e.errno)'],"
            " capture_output=True, text=True).stdout.strip())")
    assert run_locked(code).stdout.strip() == "13"


def test_cannot_remove_lock():
    # prctl/seccomp can only ADD filters; trying to reset no_new_privs fails and sockets stay blocked.
    code = ("import ctypes, socket; libc = ctypes.CDLL(None, use_errno=True); "
            "r = libc.prctl(38, 0, 0, 0, 0); "
            "ok = True\ntry:\n socket.socket()\nexcept OSError: ok = False\nprint(r, ok)")
    out = run_locked(code).stdout.split()
    assert out[0] == "-1" and out[1] == "False", out


def test_io_uring_blocked():
    code = ("import ctypes, platform; libc = ctypes.CDLL(None, use_errno=True); "
            "params = ctypes.create_string_buffer(120); "
            "r = libc.syscall(425, 8, params); print(r, ctypes.get_errno())")
    r, err = run_locked(code).stdout.split()
    assert r == "-1" and err in ("13", "1", "38"), (r, err)  # EACCES from the lock (EPERM/ENOSYS if kernel lacks it)


def test_raw_socket_syscall_blocked():
    # Bypass Python's socket module entirely: raw syscall(socket, AF_INET, SOCK_STREAM, 0).
    code = ("import ctypes, platform; libc = ctypes.CDLL(None, use_errno=True); "
            "nr = {'x86_64': 41, 'aarch64': 198}[platform.machine()]; "
            "print(libc.syscall(nr, 2, 1, 0), ctypes.get_errno())")
    assert run_locked(code).stdout.split() == ["-1", "13"]


def test_renderer_report_shows_offline_under_lock(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "note.txt").write_text("hello https://a.example/x")
    r = subprocess.run([sys.executable, "-m", "saferender.pipeline", "--in", str(tmp_path / "in"), "--out",
                        str(tmp_path / "out"), "--case", "lock1"], preexec_fn=lockdown.apply,
                       capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr[-1500:]
    rep = json.loads((tmp_path / "out" / "report.json").read_text())
    assert rep["isolation"] == {"internetReached": False, "dnsResolved": False}
