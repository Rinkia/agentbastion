"""Tool guard - the differentiator. Everyone scans prompts; few guard what the
agent actually DOES. This is where the real damage lives (mass email, delete,
external calls, exfil).

Policy is a small YAML file:

    default: deny            # deny | allow  (default when a call matches nothing)
    allow:                   # tool names the agent may call
      - get_ticket
      - search_docs
    deny:                    # explicit block (wins over allow)
      - delete_database
    rate_limits:             # optional max calls per tool this session
      send_email: 3

Decision order: deny-list -> allow-list -> default -> rate limit. `default` only
applies when there is no allow list; with one, unlisted tools are denied.

A `policy_version: 2` file adds per-detector modes (off | shadow | enforce, the
kill switch) and validates strictly; see load_policy_v2 and Firewall.from_policy.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .registry import BUILTIN_NAMESPACE, CUSTOM_NAMESPACE, MODES


@dataclass(frozen=True)
class ToolDecision:
    allowed: bool
    reason: str


class ToolBlocked(Exception):
    def __init__(self, tool: str, decision: ToolDecision) -> None:
        self.tool = tool
        self.decision = decision
        super().__init__(f"tool '{tool}' blocked: {decision.reason}")


@dataclass
class ToolPolicy:
    default: str = "deny"  # deny | allow
    allow: frozenset[str] = frozenset()
    deny: frozenset[str] = frozenset()
    rate_limits: dict[str, int] = field(default_factory=dict)
    # Per-session call counters. Stateful by nature (a guard's own bookkeeping,
    # not caller data), so mutation here is fine.
    _counts: dict[str, int] = field(default_factory=dict, repr=False)

    def check(self, tool: str, tool_input: Any = None) -> ToolDecision:
        if tool in self.deny:
            return ToolDecision(False, "on deny-list")
        if self.allow and tool not in self.allow:
            return ToolDecision(False, "not on allow-list")
        if not self.allow and self.default == "deny":
            return ToolDecision(False, "default-deny and no allow-list match")

        limit = self.rate_limits.get(tool)
        if limit is not None:
            used = self._counts.get(tool, 0)
            if used >= limit:
                return ToolDecision(False, f"rate limit reached ({limit})")

        return ToolDecision(True, "allowed")

    def record(self, tool: str) -> None:
        """Call after a tool actually runs, so rate limits count real executions."""
        self._counts[tool] = self._counts.get(tool, 0) + 1

    def enforce(self, tool: str, tool_input: Any = None) -> ToolDecision:
        """Check, raise ToolBlocked if denied, else record the call and return."""
        decision = self.check(tool, tool_input)
        if not decision.allowed:
            raise ToolBlocked(tool, decision)
        self.record(tool)
        return decision


class PolicyError(ValueError):
    """A policy file that must not load. v2 fails loudly instead of ignoring lines."""


@dataclass(frozen=True)
class PolicyV2:
    """A parsed policy: the tool policy (None = no tool policy, all tools allowed)
    plus per-detector modes for the namespaces agentbastion runs."""

    tool_policy: Optional[ToolPolicy]
    detector_modes: dict[str, str] = field(default_factory=dict)


# v2 top level = a frozen shared core + one reserved block per tool. Tool-specific
# knobs live in their tool's block, so tools can add keys without breaking each other.
_V2_CORE = frozenset({"policy_version", "default", "allow", "deny", "rate_limits", "detectors"})
_TOOL_BLOCKS = frozenset({"gate", "bastion", "supply", "skill"})
_TOOL_POLICY_LISTS = ("allow", "deny", "rate_limits")
_OWN_NAMESPACES = (BUILTIN_NAMESPACE, CUSTOM_NAMESPACE)
_FOREIGN_NAMESPACES = ("gate.", "supply.", "skill.")  # tools agentbastion never runs


def load_policy(path: str | Path) -> ToolPolicy:
    """Tool policy only (the original API). v1 files load exactly as before; v2 files
    are fully validated, and a detectors-only v2 file yields an allow-everything
    ToolPolicy (equivalent to no tool policy). Use load_policy_v2 for detector modes."""
    data = _read_mapping(path)
    if _version(data) == 2:
        policy = _parse_v2(data)
        if policy.detector_modes:
            warnings.warn(
                "load_policy() returns the tool policy only; this file's detector modes are "
                "NOT applied. Use Firewall.from_policy(path) (or fw.with_policy(path))",
                UserWarning,
                stacklevel=2,
            )
        return policy.tool_policy if policy.tool_policy is not None else ToolPolicy(default="allow")
    if "detectors" in data:
        warnings.warn(
            "`detectors:` is ignored without `policy_version: 2`; add it to enable detector modes",
            UserWarning,
            stacklevel=2,
        )
    return _tool_policy_from(data, data.get("default", "deny"))


def load_policy_v2(path: str | Path) -> PolicyV2:
    """Tool policy + detector modes. Structure is validated here; whether each
    bastion.* / custom.* ID exists is checked when a guard is built from it."""
    data = _read_mapping(path)
    if _version(data) == 2:
        return _parse_v2(data)
    if "detectors" in data:
        raise PolicyError(
            "`detectors:` requires `policy_version: 2` at the top of the file; "
            "without it the block would be silently ignored"
        )
    return PolicyV2(_tool_policy_from(data, data.get("default", "deny")))


def _read_mapping(path: str | Path) -> dict:
    import yaml

    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise PolicyError(f"policy file must be a mapping, got {type(data).__name__}")
    return data


def _version(data: dict) -> int:
    version = data.get("policy_version", 1)
    if isinstance(version, bool) or version not in (1, 2):
        raise PolicyError(f"unsupported policy_version {version!r}; this agentbastion reads 1 and 2")
    return version


def _tool_policy_from(data: dict, default: Any) -> ToolPolicy:
    return ToolPolicy(
        default=str(default).lower(),
        allow=frozenset(data.get("allow", []) or []),
        deny=frozenset(data.get("deny", []) or []),
        rate_limits=dict(data.get("rate_limits", {}) or {}),
    )


def _parse_v2(data: dict) -> PolicyV2:
    unknown = set(data) - _V2_CORE - _TOOL_BLOCKS
    if unknown:
        raise PolicyError(
            f"unknown top-level key(s) {sorted(unknown)}; policy_version 2 allows "
            f"{sorted(_V2_CORE | _TOOL_BLOCKS)}"
        )
    if data.get("bastion"):
        raise PolicyError("the `bastion:` block is reserved and must be empty in this version")
    return PolicyV2(_v2_tool_policy(data), _v2_detector_modes(data.get("detectors")))


def _v2_tool_policy(data: dict) -> Optional[ToolPolicy]:
    if "default" not in data:
        if any(key in data for key in _TOOL_POLICY_LISTS):
            raise PolicyError("`default:` (allow or deny) is required when allow, deny or rate_limits is set")
        return None  # detectors-only file: install no tool policy (all tools allowed, as today)
    default = str(data["default"]).lower()
    if default not in ("allow", "deny"):
        raise PolicyError(f"`default:` must be allow or deny, got {data['default']!r}")
    if default == "allow" and data.get("allow"):
        raise PolicyError(
            "`default: allow` contradicts a non-empty allow list: whenever an allow list exists, "
            "unlisted tools are denied. Use `default: deny`, or drop the allow list"
        )
    return _tool_policy_from(data, default)


def _v2_detector_modes(raw: Any) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError("`detectors:` must be a mapping of detector ID to off | shadow | enforce")
    modes: dict[str, str] = {}
    for det_id, mode in raw.items():
        if not isinstance(det_id, str):
            raise PolicyError(f"detector ID must be a string, got {det_id!r}")
        if det_id.startswith(_FOREIGN_NAMESPACES):
            continue  # another tool's detector; that tool validates it
        if not det_id.startswith(_OWN_NAMESPACES):
            hint = f"; did you mean {BUILTIN_NAMESPACE + det_id!r}?" if "." not in det_id else ""
            raise PolicyError(
                f"detector ID {det_id!r} has no known namespace "
                f"(bastion., custom., gate., supply., skill.){hint}"
            )
        modes[det_id] = _mode(det_id, mode)
    return modes


def _mode(det_id: str, mode: Any) -> str:
    # YAML 1.1 reads unquoted off/no/false as False; on/yes/true as True.
    if mode is False:
        return "off"
    if mode is True:
        raise PolicyError(f"detector {det_id!r}: mode `on`/`true` is ambiguous; write enforce or shadow")
    if mode not in MODES:
        raise PolicyError(f"detector {det_id!r}: mode {mode!r} is not one of off | shadow | enforce")
    return mode
