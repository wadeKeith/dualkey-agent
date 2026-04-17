from __future__ import annotations

from dataclasses import dataclass, field
import fnmatch
from pathlib import Path
import re
from typing import Any, Mapping

import yaml

from dualkey.models import ActionEnvelope, Decision, PolicyOutcome

SUPPORTED_DECISIONS = {"allow", "ask", "deny"}
MISSING = object()


def _normalize_action(action: ActionEnvelope | Mapping[str, Any]) -> ActionEnvelope:
    if isinstance(action, ActionEnvelope):
        return action
    return ActionEnvelope.from_mapping(action)


@dataclass(slots=True)
class PolicyCheck:
    label: str
    matched: bool
    detail: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "matched": self.matched,
            "detail": self.detail,
        }


@dataclass(slots=True)
class PolicyRuleTrace:
    rule_id: str
    decision: Decision
    matched: bool
    summary: str
    checks: list[PolicyCheck] = field(default_factory=list)
    skipped: bool = False

    def to_payload(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "decision": self.decision,
            "matched": self.matched,
            "summary": self.summary,
            "skipped": self.skipped,
            "checks": [check.to_payload() for check in self.checks],
        }


@dataclass(slots=True)
class PolicyExplanation:
    action: ActionEnvelope
    outcome: PolicyOutcome
    rules: list[PolicyRuleTrace] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        return {
            "action": self.action.to_payload(),
            "outcome": {
                "decision": self.outcome.decision,
                "rule_id": self.outcome.rule_id,
                "reason": self.outcome.reason,
            },
            "rules": [rule.to_payload() for rule in self.rules],
        }


@dataclass(slots=True)
class PolicyRule:
    id: str
    decision: Decision
    when: dict[str, Any] = field(default_factory=dict)

    def matches(self, action: ActionEnvelope) -> bool:
        return self.explain(action).matched

    def explain(self, action: ActionEnvelope | Mapping[str, Any]) -> PolicyRuleTrace:
        envelope = _normalize_action(action)
        checks: list[PolicyCheck] = []

        exact_fields = ("actor", "surface", "tool", "intent")
        for field_name in exact_fields:
            expected = self.when.get(field_name)
            if expected is None:
                continue
            actual = getattr(envelope, field_name)
            checks.append(
                _make_check(
                    label=field_name,
                    matched=actual == expected,
                    detail_ok=f"{field_name} matched {expected!r}",
                    detail_fail=f"{field_name} expected {expected!r}, got {actual!r}",
                )
            )

        for field_name in exact_fields:
            pattern = self.when.get(f"{field_name}_glob")
            if pattern is None:
                continue
            actual = getattr(envelope, field_name)
            checks.append(
                _make_check(
                    label=f"{field_name}_glob",
                    matched=_match_glob(actual, pattern),
                    detail_ok=f"{field_name}_glob matched {pattern!r}",
                    detail_fail=f"{field_name}_glob {pattern!r} did not match {actual!r}",
                )
            )

        target = envelope.target or str(envelope.args.get("path", ""))

        target_prefix = self.when.get("target_prefix")
        if target_prefix is not None:
            prefix = str(target_prefix)
            checks.append(
                _make_check(
                    label="target_prefix",
                    matched=target.startswith(prefix),
                    detail_ok=f"target_prefix matched {prefix!r}",
                    detail_fail=f"target_prefix {prefix!r} did not match {target!r}",
                )
            )

        target_glob = self.when.get("target_glob")
        if target_glob is not None:
            checks.append(
                _make_check(
                    label="target_glob",
                    matched=_match_glob(target, target_glob),
                    detail_ok=f"target_glob matched {target_glob!r}",
                    detail_fail=f"target_glob {target_glob!r} did not match {target!r}",
                )
            )

        target_regex = self.when.get("target_regex")
        if target_regex is not None:
            checks.append(
                _make_check(
                    label="target_regex",
                    matched=_match_regex(target, target_regex),
                    detail_ok=f"target_regex matched {target_regex!r}",
                    detail_fail=f"target_regex {target_regex!r} did not match {target!r}",
                )
            )

        tool_in = self.when.get("tool_in")
        if tool_in is not None:
            options = [str(item) for item in _ensure_sequence(tool_in)]
            checks.append(
                _make_check(
                    label="tool_in",
                    matched=envelope.tool in set(options),
                    detail_ok=f"tool {envelope.tool!r} is in tool_in",
                    detail_fail=f"tool {envelope.tool!r} is not in {options!r}",
                )
            )

        tags_any = self.when.get("tags_any")
        if tags_any is not None:
            required = [str(item) for item in _ensure_sequence(tags_any)]
            overlap = sorted(set(envelope.risk).intersection(required))
            checks.append(
                _make_check(
                    label="tags_any",
                    matched=bool(overlap),
                    detail_ok=f"tags_any matched on {overlap!r}",
                    detail_fail=f"tags_any expected overlap with {required!r}, got {envelope.risk!r}",
                )
            )

        tags_all = self.when.get("tags_all")
        if tags_all is not None:
            required = [str(item) for item in _ensure_sequence(tags_all)]
            missing = [tag for tag in required if tag not in envelope.risk]
            checks.append(
                _make_check(
                    label="tags_all",
                    matched=not missing,
                    detail_ok=f"tags_all matched {required!r}",
                    detail_fail=f"tags_all missing {missing!r} from {envelope.risk!r}",
                )
            )

        tags_none = self.when.get("tags_none")
        if tags_none is not None:
            forbidden = [str(item) for item in _ensure_sequence(tags_none)]
            overlap = [tag for tag in envelope.risk if tag in forbidden]
            checks.append(
                _make_check(
                    label="tags_none",
                    matched=not overlap,
                    detail_ok=f"tags_none avoided {forbidden!r}",
                    detail_fail=f"tags_none forbids {overlap!r}",
                )
            )

        command_matches = self.when.get("command_matches")
        if command_matches is not None:
            command = str(envelope.args.get("command", ""))
            snippets = [str(item) for item in _ensure_sequence(command_matches)]
            matched_snippet = next((snippet for snippet in snippets if snippet in command), None)
            checks.append(
                _make_check(
                    label="command_matches",
                    matched=matched_snippet is not None,
                    detail_ok=f"command matched snippet {matched_snippet!r}",
                    detail_fail=f"command did not contain any of {snippets!r}: {command!r}",
                )
            )

        checks.extend(_mapping_policy_checks(envelope.args, self.when.get("arg_equals"), _match_equals, "arg_equals"))
        checks.extend(_mapping_policy_checks(envelope.args, self.when.get("arg_prefix"), _match_prefix, "arg_prefix"))
        checks.extend(_mapping_policy_checks(envelope.args, self.when.get("arg_contains"), _match_contains, "arg_contains"))
        checks.extend(_mapping_policy_checks(envelope.args, self.when.get("arg_glob"), _match_glob, "arg_glob"))
        checks.extend(_mapping_policy_checks(envelope.args, self.when.get("arg_regex"), _match_regex, "arg_regex"))
        checks.extend(_exists_policy_checks(envelope.args, self.when.get("arg_exists"), "arg_exists"))

        checks.extend(
            _mapping_policy_checks(envelope.metadata, self.when.get("metadata_equals"), _match_equals, "metadata_equals")
        )
        checks.extend(
            _mapping_policy_checks(
                envelope.metadata,
                self.when.get("metadata_contains"),
                _match_contains,
                "metadata_contains",
            )
        )
        checks.extend(
            _mapping_policy_checks(envelope.metadata, self.when.get("metadata_glob"), _match_glob, "metadata_glob")
        )
        checks.extend(
            _mapping_policy_checks(envelope.metadata, self.when.get("metadata_regex"), _match_regex, "metadata_regex")
        )
        checks.extend(_exists_policy_checks(envelope.metadata, self.when.get("metadata_exists"), "metadata_exists"))

        matched = all(check.matched for check in checks)
        if not checks:
            summary = "matched because the rule has no conditions"
        elif matched:
            summary = f"matched {len(checks)} configured conditions"
        else:
            summary = next(check.detail for check in checks if not check.matched)
        return PolicyRuleTrace(
            rule_id=self.id,
            decision=self.decision,
            matched=matched,
            summary=summary,
            checks=checks,
        )


@dataclass(slots=True)
class Policy:
    default_decision: Decision = "ask"
    rules: list[PolicyRule] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "Policy":
        default_decision = str(payload.get("default_decision", "ask"))
        if default_decision not in SUPPORTED_DECISIONS:
            raise ValueError(f"Unsupported default decision: {default_decision}")

        rules: list[PolicyRule] = []
        for index, raw_rule in enumerate(payload.get("rules", []), start=1):
            decision = str(raw_rule["decision"])
            if decision not in SUPPORTED_DECISIONS:
                raise ValueError(f"Unsupported decision in rule {index}: {decision}")
            rules.append(
                PolicyRule(
                    id=str(raw_rule.get("id", f"rule_{index}")),
                    decision=decision,  # type: ignore[arg-type]
                    when=dict(raw_rule.get("when", {})),
                )
            )
        return cls(default_decision=default_decision, rules=rules)  # type: ignore[arg-type]

    def evaluate(self, action: ActionEnvelope | Mapping[str, Any]) -> PolicyOutcome:
        envelope = _normalize_action(action)
        for rule in self.rules:
            if rule.matches(envelope):
                return PolicyOutcome(
                    decision=rule.decision,
                    rule_id=rule.id,
                    reason=f"matched rule '{rule.id}'",
                )
        return PolicyOutcome(
            decision=self.default_decision,
            rule_id="default",
            reason="fell through to default decision",
        )

    def explain(self, action: ActionEnvelope | Mapping[str, Any]) -> PolicyExplanation:
        envelope = _normalize_action(action)
        traces: list[PolicyRuleTrace] = []
        matched_rule_id: str | None = None

        for rule in self.rules:
            if matched_rule_id is not None:
                traces.append(
                    PolicyRuleTrace(
                        rule_id=rule.id,
                        decision=rule.decision,
                        matched=False,
                        skipped=True,
                        summary=f"skipped because rule '{matched_rule_id}' already matched",
                    )
                )
                continue
            trace = rule.explain(envelope)
            traces.append(trace)
            if trace.matched:
                matched_rule_id = rule.id

        outcome = self.evaluate(envelope)
        if outcome.rule_id == "default":
            traces.append(
                PolicyRuleTrace(
                    rule_id="default",
                    decision=self.default_decision,
                    matched=True,
                    skipped=False,
                    summary="fell through to default decision",
                )
            )
        return PolicyExplanation(action=envelope, outcome=outcome, rules=traces)


def load_policy(path_or_payload: str | Path | Mapping[str, Any] | Policy) -> Policy:
    if isinstance(path_or_payload, Policy):
        return path_or_payload
    if isinstance(path_or_payload, Mapping):
        return Policy.from_mapping(path_or_payload)

    path = Path(path_or_payload)
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    return Policy.from_mapping(payload)


def _make_check(*, label: str, matched: bool, detail_ok: str, detail_fail: str) -> PolicyCheck:
    return PolicyCheck(label=label, matched=matched, detail=detail_ok if matched else detail_fail)


def _mapping_policy_checks(
    payload: Mapping[str, Any],
    conditions: Any,
    predicate: Any,
    label: str,
) -> list[PolicyCheck]:
    if not conditions:
        return []
    checks: list[PolicyCheck] = []
    for path, expected in dict(conditions).items():
        actual = _resolve_path(payload, str(path))
        if actual is MISSING:
            checks.append(PolicyCheck(label=f"{label}.{path}", matched=False, detail=f"{label}.{path} missing"))
            continue
        matched = predicate(actual, expected)
        checks.append(
            _make_check(
                label=f"{label}.{path}",
                matched=matched,
                detail_ok=f"{label}.{path} matched {_stringify_value(expected)!r}",
                detail_fail=(
                    f"{label}.{path} expected {_stringify_value(expected)!r}, "
                    f"got {_stringify_value(actual)!r}"
                ),
            )
        )
    return checks


def _exists_policy_checks(payload: Mapping[str, Any], paths: Any, label: str) -> list[PolicyCheck]:
    if not paths:
        return []
    checks: list[PolicyCheck] = []
    for path in _ensure_sequence(paths):
        exists = _resolve_path(payload, str(path)) is not MISSING
        checks.append(
            _make_check(
                label=f"{label}.{path}",
                matched=exists,
                detail_ok=f"{label}.{path} exists",
                detail_fail=f"{label}.{path} missing",
            )
        )
    return checks


def _resolve_path(payload: Any, path: str) -> Any:
    current = payload
    for part in str(path).split("."):
        if isinstance(current, Mapping):
            if part not in current:
                return MISSING
            current = current[part]
            continue
        if isinstance(current, list):
            if not part.isdigit():
                return MISSING
            index = int(part)
            if index < 0 or index >= len(current):
                return MISSING
            current = current[index]
            continue
        return MISSING
    return current


def _match_exists(payload: Mapping[str, Any], paths: Any) -> bool:
    for path in _ensure_sequence(paths):
        if _resolve_path(payload, str(path)) is MISSING:
            return False
    return True


def _match_mapping_predicate(
    payload: Mapping[str, Any],
    conditions: Mapping[str, Any],
    predicate: Any,
) -> bool:
    for path, expected in conditions.items():
        actual = _resolve_path(payload, str(path))
        if actual is MISSING:
            return False
        if not predicate(actual, expected):
            return False
    return True


def _match_equals(actual: Any, expected: Any) -> bool:
    if actual == expected:
        return True
    return any(value == str(expected) for value in _leaf_strings(actual))


def _match_prefix(actual: Any, expected: Any) -> bool:
    prefixes = [str(item) for item in _ensure_sequence(expected)]
    return any(value.startswith(prefix) for value in _leaf_strings(actual) for prefix in prefixes)


def _match_contains(actual: Any, expected: Any) -> bool:
    needles = [str(item) for item in _ensure_sequence(expected)]
    return any(needle in value for value in _leaf_strings(actual) for needle in needles)


def _match_glob(actual: Any, expected: Any) -> bool:
    patterns = [str(item) for item in _ensure_sequence(expected)]
    return any(fnmatch.fnmatchcase(value, pattern) for value in _leaf_strings(actual) for pattern in patterns)


def _match_regex(actual: Any, expected: Any) -> bool:
    patterns = [re.compile(str(item)) for item in _ensure_sequence(expected)]
    return any(pattern.search(value) for value in _leaf_strings(actual) for pattern in patterns)


def _ensure_sequence(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _leaf_strings(value: Any) -> list[str]:
    if value is MISSING:
        return []
    if isinstance(value, dict):
        return [yaml.safe_dump(value, sort_keys=True).strip()]
    if isinstance(value, (list, tuple, set)):
        strings: list[str] = []
        for item in value:
            strings.extend(_leaf_strings(item))
        return strings
    return [str(value)]


def _stringify_value(value: Any) -> str:
    if value is MISSING:
        return "<missing>"
    if isinstance(value, str):
        return value
    return yaml.safe_dump(value, sort_keys=True).strip()
