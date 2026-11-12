# hal-id: #HAL-20261111-0001-PK-R6
"""Kernel-enforced "no network" for the renderer, without needing a network-less container.

Cloud container platforms (e.g. Azure Container Apps) don't offer `docker run --network none`, and the fetcher
needs the network to download the case. So the fetcher starts the renderer under a seccomp filter that the Linux
kernel enforces on the renderer and everything it launches (LibreOffice, tesseract, ClamAV):

  * socket() for any address family except AF_UNIX  -> EACCES   (no TCP, UDP, DNS, raw, netlink, ...)
  * io_uring_setup()                                 -> EACCES   (io_uring can open sockets without socket())
  * any syscall from a foreign ABI (32-bit/x32)      -> process killed (the classic seccomp bypass)

It can't be undone: seccomp filters can only be added, never removed, and no_new_privs stops setuid escapes.
Pure ctypes, no compiled dependency. Linux x86_64 and aarch64.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import subprocess
import sys

# Linux constants (include/uapi/linux/{prctl,seccomp,audit,filter}.h)
PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 38, 22, 2
RET_KILL_PROCESS, RET_ALLOW, RET_ERRNO = 0x80000000, 0x7FFF0000, 0x00050000
EACCES, AF_UNIX = 13, 1
LD_W_ABS, JEQ_K, JGE_K, RET_K = 0x20, 0x15, 0x35, 0x06
ARCHES = {  # machine -> (AUDIT_ARCH, nr(socket), nr(io_uring_setup))
    "x86_64": (0xC000003E, 41, 425),
    "aarch64": (0xC00000B7, 198, 425),
}
X32_BIT = 0x40000000


class _Insn(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _Prog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_Insn))]


def _program() -> list[tuple[int, int, int, int]]:
    arch, nr_socket, nr_uring = ARCHES[platform.machine()]
    # seccomp_data: nr @0, arch @4, args[0] (low 32 bits, little-endian) @16. Jumps are relative to the next insn.
    return [
        (LD_W_ABS, 0, 0, 4),                    # 0  A = arch
        (JEQ_K, 1, 0, arch),                    # 1  native ABI? -> 3
        (RET_K, 0, 0, RET_KILL_PROCESS),        # 2  foreign ABI: kill
        (LD_W_ABS, 0, 0, 0),                    # 3  A = syscall nr
        (JGE_K, 6, 0, X32_BIT),                 # 4  x32 ABI -> 11 (kill)
        (JEQ_K, 4, 0, nr_uring),                # 5  io_uring_setup -> 10 (deny)
        (JEQ_K, 0, 2, nr_socket),               # 6  socket -> 7, else -> 9 (allow)
        (LD_W_ABS, 0, 0, 16),                   # 7  A = domain (args[0])
        (JEQ_K, 0, 1, AF_UNIX),                 # 8  AF_UNIX -> 9 (allow), else -> 10 (deny)
        (RET_K, 0, 0, RET_ALLOW),               # 9
        (RET_K, 0, 0, RET_ERRNO | EACCES),      # 10
        (RET_K, 0, 0, RET_KILL_PROCESS),        # 11
    ]


def apply() -> None:
    """Lock the CURRENT process (and all future children) out of the network. Irreversible.
    Safe to use as subprocess preexec_fn (runs in the child between fork and exec)."""
    if platform.system() != "Linux" or platform.machine() not in ARCHES:
        raise OSError("lockdown supports Linux x86_64/aarch64 only")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    insns = _program()
    arr = (_Insn * len(insns))(*[_Insn(*i) for i in insns])
    prog = _Prog(len(insns), arr)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(prog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "seccomp filter install failed")


_PROBE = r"""
import json, socket
out = {}
for name, fam, typ in [("tcp4", socket.AF_INET, socket.SOCK_STREAM), ("udp4", socket.AF_INET, socket.SOCK_DGRAM),
                       ("tcp6", socket.AF_INET6, socket.SOCK_STREAM), ("netlink", socket.AF_NETLINK, socket.SOCK_RAW)]:
    try:
        socket.socket(fam, typ).close(); out[name] = "open"
    except OSError as e:
        out[name] = "blocked" if e.errno == 13 else f"error {e.errno}"
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close(); out["unix"] = "open"
except OSError as e:
    out["unix"] = f"error {e.errno}"
try:
    socket.getaddrinfo("www.microsoft.com", 443); out["dns"] = "resolved"
except OSError:
    out["dns"] = "failed"
print(json.dumps(out))
"""


def verify() -> dict:
    """Prove the lock works on THIS host, right now: start a throwaway child under the same filter and try to open
    network sockets. Recorded in every case's attestation, so each case carries its own evidence."""
    try:
        r = subprocess.run([sys.executable, "-I", "-c", _PROBE], preexec_fn=apply, capture_output=True, text=True,
                           timeout=30, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        probe = json.loads(r.stdout or "{}")
    except Exception as e:  # noqa: BLE001 - any failure means "not verified"
        return {"verified": False, "error": f"{type(e).__name__}: {e}"[:300]}
    ok = all(probe.get(k) == "blocked" for k in ("tcp4", "udp4", "tcp6", "netlink")) and probe.get("dns") == "failed" \
        and probe.get("unix") == "open"
    return {"verified": ok, "probe": probe, "arch": platform.machine()}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=1))
