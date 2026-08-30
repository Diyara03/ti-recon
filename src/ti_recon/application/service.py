"""The transport-neutral entry point (Task 20).

One object that turns analyst input into an analyst report, with no idea what is
calling it. A CLI uses it, an MCP server will use it, and a UI could — and
because they share it, none of them has to interpret the investigation engine
and none of them can drift from the others.

Everything interface-shaped stays out: no argument parsing, no stdout, no exit
codes, no protocol. Everything engine-shaped stays out too: no provider choice,
no verdict, no readiness. What is left is the join between the two — canonicalise
the input, run the workflow, project the result.
"""

from __future__ import annotations

import hashlib
import stat
from dataclasses import dataclass
from pathlib import Path

from ti_recon.application.models import AnalystInvestigationRequest, ObservableInputType
from ti_recon.correlation.policy import PivotPolicy
from ti_recon.execution.models import ExecutionContext
from ti_recon.investigation import InvestigationRequest, InvestigationResult
from ti_recon.investigation.engine import InvestigationOrchestrator
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import (
    NormalizationError,
    normalize_domain,
    normalize_file_hash,
    normalize_ip,
    normalize_observable,
    normalize_url,
)
from ti_recon.reporting.builder import build_analyst_report
from ti_recon.reporting.models import AnalystInvestigationReport

__all__ = [
    "FILE_HASH_ALGORITHM",
    "InvalidObservableError",
    "InvestigationApplication",
    "hash_local_file",
    "resolve_observable",
]

#: The digest computed for a local file.
#:
#: SHA-256 because it is the identity the engine treats as authoritative: a
#: weaker digest merges two samples only when nothing stronger disagrees, and
#: submitting the strongest available identity avoids that question entirely.
FILE_HASH_ALGORITHM: str = "sha256"

#: How much of a file is read at a time. The file is hashed, never held.
_READ_CHUNK: int = 1024 * 1024


class InvalidObservableError(ValueError):
    """The caller's input is not something this engine can investigate.

    An input failure, raised before any provider is contacted. Deliberately not
    an analytical outcome: an unparseable value has not been found inconclusive,
    it has not been investigated at all, and reporting it as a verdict would
    invent a result nobody produced.
    """


def resolve_observable(request: AnalystInvestigationRequest) -> IntelObject:
    """Turn analyst text into the canonical object the engine expects.

    Every branch delegates to the repository's own normalizer. There is no
    second parser here: a URL, a domain, an address and a digest each already
    have canonicalisation rules — defanging, IDNA, digest length — and a
    reimplementation would be a slightly different set of rules reached by a
    different door.

    Purely local. Nothing resolves a name, opens a socket or asks a provider;
    a domain that does not exist canonicalises exactly like one that does,
    because whether it exists is a question for the investigation.
    """
    raw = request.observable.strip()
    try:
        match request.observable_type:
            case ObservableInputType.AUTO:
                return normalize_observable(raw).intel_object
            case ObservableInputType.URL:
                return normalize_url(raw)
            case ObservableInputType.DOMAIN:
                return normalize_domain(raw)
            case ObservableInputType.FILE_HASH:
                return normalize_file_hash(raw)
            case ObservableInputType.IPV4 | ObservableInputType.IPV6:
                return _address(raw, request.observable_type)
    except NormalizationError as error:
        raise InvalidObservableError(str(error)) from error


def _address(raw: str, requested: ObservableInputType) -> IntelObject:
    """An address, checked against the family the caller named.

    The normalizer accepts either family, so asking for one and receiving the
    other would silently investigate something the caller did not describe —
    which matters most for the colon-bearing values that are easy to confuse.
    """
    intel_object = normalize_ip(raw)
    expected = {
        ObservableInputType.IPV4: "ipv4-addr",
        ObservableInputType.IPV6: "ipv6-addr",
    }[requested]
    if intel_object.object_type.value != expected:
        msg = f"expected {requested.value} but {raw!r} is {intel_object.object_type.value}"
        raise InvalidObservableError(msg)
    return intel_object


def hash_local_file(path: Path) -> str:
    """The SHA-256 of a local file, computed here and nowhere else.

    The *only* thing that leaves this function is a digest. The bytes are read
    a megabyte at a time, hashed, and discarded — never accumulated, so a large
    sample costs a constant amount of memory — and nothing uploads the file,
    submits it for detonation, or puts its content in a provider request. A hash
    lookup asks "has anyone seen this exact sample?", which is a question a
    sample's owner can ask without handing the sample to anybody.

    **Regular files only.** Opening a FIFO blocks until somebody writes to it,
    and a character device can be endless, so either would hang the command with
    no output and no way to tell why. The check is against the *resolved* target,
    so a symlink to a real file is followed deliberately — an analyst pointing at
    a symlink means the file — while a symlink to a pipe is refused like the pipe
    it is.
    """
    try:
        status = path.stat()
    except OSError as error:
        msg = f"cannot read {path}: {error.strerror or type(error).__name__}"
        raise InvalidObservableError(msg) from error
    if not stat.S_ISREG(status.st_mode):
        msg = f"{path} is not a regular file"
        raise InvalidObservableError(msg)

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_READ_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class InvestigationApplication:
    """Analyst input in, analyst report out.

    The orchestrator is injected rather than built here: composing one needs
    adapters, credentials, a cache and an executor, and that is deployment
    configuration rather than an application concern. Keeping it out also means
    a caller can hand in a fully faked stack and get the identical report.
    """

    orchestrator: InvestigationOrchestrator

    async def investigate(
        self,
        request: AnalystInvestigationRequest,
        context: ExecutionContext,
    ) -> AnalystInvestigationReport:
        """Run one investigation and return the public report.

        ``context`` is required rather than defaulted. It carries the identity
        every cache, quota, cooldown and credential lookup below is keyed by, so
        inventing one here would be this layer choosing whose isolation boundary
        somebody else's work runs in.
        """
        result = await self.run(request, context)
        return build_analyst_report(result)

    async def run(
        self,
        request: AnalystInvestigationRequest,
        context: ExecutionContext,
    ) -> InvestigationResult:
        """The full internal result, for a caller that needs the whole trace.

        Kept available on purpose: the report is the *supported* contract, not a
        wall. Debugging a disagreement between layers needs the planner
        decisions and graph the report deliberately leaves out.
        """
        root = resolve_observable(request)
        return await self.orchestrator.investigate(
            InvestigationRequest(root=root, depth=request.depth),
            context,
            pivot_policy=PivotPolicy(mode=request.pivot_mode),
        )
