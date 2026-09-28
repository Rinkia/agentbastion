"""policy.yaml loader: v1 stays byte-for-byte, v2 validates strictly.

Rules (design A1, eng review decisions 2A / 3B / OV1 / OV2):
- no policy_version, or 1 -> v1: today's lenient behavior, no detector modes
- 2 -> v2: frozen core keys + reserved per-tool blocks; anything else raises
- `default` is required only when allow/deny/rate_limits is present (OV1);
  a detectors-only file installs no tool policy, so all tools stay allowed
- `default: allow` with a non-empty allow list is a contradiction and raises (OV2)
- detector IDs are namespaced; bastion.* / custom.* are kept for the guard to
  validate (existence is checked at guard construction, 3B); gate.* / supply.* /
  skill.* belong to tools agentbastion never runs and are ignored
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentbastion.tools import PolicyError, ToolPolicy, load_policy, load_policy_v2

GOLDEN_V1 = Path(__file__).parent / "fixtures" / "policy_golden.yaml"


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _fields(tp: ToolPolicy) -> tuple:
    return tp.default, tp.allow, tp.deny, tp.rate_limits


# --- v1: unchanged ---------------------------------------------------------

def test_v1_golden_loads_identically_through_both_loaders():
    v2 = load_policy_v2(GOLDEN_V1)
    assert _fields(v2.tool_policy) == _fields(load_policy(GOLDEN_V1))
    assert v2.detector_modes == {}


def test_explicit_version_1_is_v1(tmp_path):
    path = _write(tmp_path, "policy_version: 1\nallow: [read_file]\n")
    assert _fields(load_policy_v2(path).tool_policy) == _fields(load_policy(path))


def test_v1_missing_default_keeps_todays_implicit_deny(tmp_path):
    path = _write(tmp_path, "deny: [run_task]\n")
    assert load_policy_v2(path).tool_policy.default == "deny"


def test_detectors_without_version_2_raises_in_v2_loader(tmp_path):
    path = _write(tmp_path, "default: allow\ndetectors:\n  bastion.exfil_action: off\n")
    with pytest.raises(PolicyError, match="policy_version: 2"):
        load_policy_v2(path)


def test_detectors_without_version_2_warns_in_legacy_loader(tmp_path):
    path = _write(tmp_path, "default: allow\ndetectors:\n  bastion.exfil_action: off\n")
    with pytest.warns(UserWarning, match="policy_version: 2"):
        load_policy(path)


# --- v2: happy paths -------------------------------------------------------

def test_v2_kill_switch_with_default(tmp_path):
    path = _write(tmp_path, "policy_version: 2\ndefault: allow\ndetectors:\n  bastion.exfil_action: off\n")
    policy = load_policy_v2(path)
    assert policy.tool_policy.default == "allow"
    assert policy.detector_modes == {"bastion.exfil_action": "off"}


def test_v2_detectors_only_installs_no_tool_policy(tmp_path):
    path = _write(tmp_path, "policy_version: 2\ndetectors:\n  bastion.exfil_action: off\n")
    policy = load_policy_v2(path)
    assert policy.tool_policy is None  # all tools stay allowed, as with no policy today


def test_v2_full_tool_policy(tmp_path):
    path = _write(tmp_path, (
        "policy_version: 2\ndefault: deny\nallow: [read_file, list_files]\n"
        "deny: [run_task]\nrate_limits: {read_file: 5}\n"
    ))
    tp = load_policy_v2(path).tool_policy
    assert _fields(tp) == ("deny", frozenset({"read_file", "list_files"}), frozenset({"run_task"}),
                           {"read_file": 5})


def test_v2_keeps_bastion_and_custom_modes(tmp_path):
    path = _write(tmp_path, (
        "policy_version: 2\ndetectors:\n  bastion.exfil_action: off\n"
        "  bastion.judge: shadow\n  custom.my_rule: enforce\n"
    ))
    assert load_policy_v2(path).detector_modes == {
        "bastion.exfil_action": "off", "bastion.judge": "shadow", "custom.my_rule": "enforce",
    }


def test_v2_ignores_namespaces_agentbastion_never_runs(tmp_path):
    path = _write(tmp_path, (
        "policy_version: 2\ndetectors:\n  gate.poisoned_tool: off\n"
        "  supply.tool_poisoning: shadow\n  skill.egress: off\n"
    ))
    assert load_policy_v2(path).detector_modes == {}


def test_v2_ignores_other_tools_blocks(tmp_path):
    path = _write(tmp_path, "policy_version: 2\ngate:\n  scan_results: true\n  anything: [1, 2]\n")
    assert load_policy_v2(path).tool_policy is None


def test_v2_empty_bastion_block_is_allowed(tmp_path):
    path = _write(tmp_path, "policy_version: 2\nbastion: {}\n")
    assert load_policy_v2(path).detector_modes == {}


def test_v2_unknown_bastion_id_is_left_for_the_guard(tmp_path):
    # ID existence is validated at guard construction against the runtime set (3B).
    path = _write(tmp_path, "policy_version: 2\ndetectors:\n  bastion.not_a_rule: off\n")
    assert load_policy_v2(path).detector_modes == {"bastion.not_a_rule": "off"}


# --- v2: strict errors -----------------------------------------------------

@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("policy_version: 2\ndetecters:\n  bastion.exfil_action: off\n", "detecters"),
        ("policy_version: 2\nallow: [read_file]\n", "default"),
        ("policy_version: 2\ndeny: [run_task]\n", "default"),
        ("policy_version: 2\nrate_limits: {read_file: 5}\n", "default"),
        ("policy_version: 2\ndefault: allow\nallow: [read_file]\n", "contradict"),
        ("policy_version: 2\ndefault: maybe\n", "default"),
        ("policy_version: 2\ndetectors:\n  bastion.exfil_action: disable\n", "disable"),
        ("policy_version: 2\ndetectors:\n  exfil_action: off\n", "bastion.exfil_action"),
        ("policy_version: 2\ndetectors:\n  foo.bar: off\n", "foo.bar"),
        ("policy_version: 2\ndetectors: [bastion.exfil_action]\n", "detectors"),
        ("policy_version: 2\nbastion:\n  block_threshold: 3\n", "bastion"),
        ("policy_version: 3\n", "policy_version"),
        ("- just\n- a list\n", "mapping"),
    ],
)
def test_v2_rejects(tmp_path, text, needle):
    with pytest.raises(PolicyError, match=needle):
        load_policy_v2(_write(tmp_path, text))


def test_policy_error_is_a_value_error():
    assert issubclass(PolicyError, ValueError)


# --- legacy load_policy on v2 files ----------------------------------------

def test_legacy_loader_reads_v2_tool_policy(tmp_path):
    path = _write(tmp_path, "policy_version: 2\ndefault: deny\nallow: [read_file]\n")
    tp = load_policy(path)
    assert isinstance(tp, ToolPolicy)
    assert tp.check("read_file").allowed and not tp.check("run_task").allowed


def test_legacy_loader_on_detectors_only_v2_allows_every_tool(tmp_path):
    path = _write(tmp_path, "policy_version: 2\ndetectors:\n  bastion.exfil_action: off\n")
    tp = load_policy(path)
    assert isinstance(tp, ToolPolicy)
    assert tp.check("run_task").allowed and tp.check("send_email").allowed


def test_legacy_loader_validates_v2_files(tmp_path):
    with pytest.raises(PolicyError, match="detecters"):
        load_policy(_write(tmp_path, "policy_version: 2\ndetecters: {}\n"))


def test_legacy_loader_warns_that_v2_detector_modes_are_not_applied(tmp_path):
    # Reproduction path #1: `fw.tool_policy = load_policy(path)` can only carry the tool
    # policy, so a kill switch in the file would be dropped. It must not be silent.
    path = _write(tmp_path, "policy_version: 2\ndetectors:\n  bastion.exfil_action: off\n")
    with pytest.warns(UserWarning, match="Firewall.from_policy"):
        load_policy(path)


def test_legacy_loader_is_quiet_for_v2_without_detectors(tmp_path, recwarn):
    load_policy(_write(tmp_path, "policy_version: 2\ndefault: deny\n"))
    assert not [w for w in recwarn if issubclass(w.category, UserWarning)]
