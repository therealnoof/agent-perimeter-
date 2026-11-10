"""perimeter_client: the worker-side library for talking to agentd.

This is deliberately tiny. An agent framework calls ``propose(tool, args)`` and
gets back either a result or a typed refusal. There is nothing else to learn.

How the connection works: agentd starts the worker with one end of a
``socketpair(2)`` already open on file descriptor 3 (the ``PERIMETER_FD``
environment variable says which, in case that ever changes). We never open a
socket ourselves; we just use the fd we were handed. If it is not there, we
are not running under the governor and we refuse to pretend otherwise.

Wire format: 4-byte big-endian length, then that many bytes of JSON.

What this library must never do:
  * Report data labels, taint, or call counts to the governor. The governor
    tracks those itself (requirement D-2 / G-7); anything we said would be
    ignored, so we do not say it.
  * Retry a denial with a different justification. The justification never
    reaches policy (P-2), so a retry is just noise in the audit log.
"""

from __future__ import annotations

import json
import os
import platform
import struct
from dataclasses import dataclass
from typing import Any

__all__ = ["propose", "Denied", "PendingApproval", "NotUnderGovernor"]

__version__ = "0.3"

# Sent with every request as the "client" field. Observational only: the
# governor records it for fingerprinting and never decides on it.
CLIENT = f"perimeter_client/{__version__} python/{platform.python_version()}"


class NotUnderGovernor(RuntimeError):
    """Raised when the inherited socket fd is missing: we were not started by agentd."""


@dataclass
class Denied(Exception):
    """The governor refused the action. Structured, no prose (requirement A-4)."""

    reason_code: str
    rule: str

    def __str__(self) -> str:  # so it prints usefully in agent logs
        return f"denied: {self.reason_code} ({self.rule})"


@dataclass
class PendingApproval(Exception):
    """The governor routed the action to a human. The action has NOT run."""

    reason_code: str
    rule: str

    def __str__(self) -> str:
        return f"pending human approval: {self.reason_code} ({self.rule})"


def _fd() -> int:
    """Return the governor socket fd, or raise if we are not under agentd."""
    raw = os.environ.get("PERIMETER_FD", "3")
    try:
        fd = int(raw)
        os.fstat(fd)  # raises if the fd is not open
    except (ValueError, OSError) as e:
        raise NotUnderGovernor("no governor socket on fd %s" % raw) from e
    return fd


def _read_exact(fd: int, n: int) -> bytes:
    """Read exactly n bytes from fd. A short read means the governor is gone."""
    buf = bytearray()
    while len(buf) < n:
        chunk = os.read(fd, n - len(buf))
        if not chunk:
            raise NotUnderGovernor("governor closed the socket")
        buf += chunk
    return bytes(buf)


def propose(tool: str, args: dict[str, Any], task_id: str, justification: str = "") -> Any:
    """Ask the governor to run ``tool`` with ``args`` on behalf of ``task_id``.

    Returns the tool's result on ``allow``. Raises ``Denied`` on ``deny`` and
    ``PendingApproval`` on ``approve``. The ``justification`` is carried for
    the human approver's optional view; it has no effect on the decision.
    """
    fd = _fd()
    frame = json.dumps(
        {"tool": tool, "args": args, "task_id": task_id, "justification": justification, "client": CLIENT},
        separators=(",", ":"),
    ).encode()
    os.write(fd, struct.pack(">I", len(frame)) + frame)

    (n,) = struct.unpack(">I", _read_exact(fd, 4))
    resp = json.loads(_read_exact(fd, n))

    verdict = resp.get("verdict")
    if verdict == "allow":
        return resp.get("result")
    if verdict == "approve":
        raise PendingApproval(resp.get("reason_code", ""), resp.get("rule", ""))
    raise Denied(resp.get("reason_code", "unknown"), resp.get("rule", ""))
