from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

try:
    from slither import Slither  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Slither = None


ETH_CALL_PATTERNS = (
    re.compile(r"\.call\s*\{", re.IGNORECASE),
    re.compile(r"\.call\s*\(", re.IGNORECASE),
    re.compile(r"\.transfer\s*\(", re.IGNORECASE),
    re.compile(r"\.send\s*\(", re.IGNORECASE),
)

GENERIC_EXTERNAL_CALL_PATTERN = re.compile(
    r"(?:\b[A-Za-z_][A-Za-z0-9_]*|\))\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(",
    re.IGNORECASE,
)
FUNCTION_LIKE_PATTERN = re.compile(
    r"^\s*(function|modifier|constructor|fallback|receive)\b",
    re.IGNORECASE | re.MULTILINE,
)
MODIFIER_NAME_PATTERN = re.compile(
    r"\b(?!external\b|public\b|private\b|internal\b|payable\b|view\b|pure\b|virtual\b|override\b|returns\b|memory\b|calldata\b|storage\b)([A-Za-z_][A-Za-z0-9_]*)\b"
)
ASSIGNMENT_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]+\])?\s*(?:\+|-|\*|/)?=")
PROMPT_REDACTION_PATTERNS = (
    (re.compile(r"__(?:insecure|fixed)\b", re.IGNORECASE), "__sample"),
    (re.compile(r"\b(?:Insecure|Fixed)([A-Z][A-Za-z0-9_]*)\b"), r"Sample\1"),
    (re.compile(r"\b(?:Insecure|Fixed)\b", re.IGNORECASE), "Sample"),
)


def redact_prompt_text(text: str) -> str:
    for pattern, replacement in PROMPT_REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


@dataclass
class SourceUnit:
    path: str
    content: str


@dataclass
class StaticFinding:
    contract_name: str
    symbol_name: str
    symbol_type: str
    source_code: str
    reasons: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    state_reads: list[str] = field(default_factory=list)
    state_writes: list[str] = field(default_factory=list)
    can_send_eth: bool = False
    post_interaction_state_update: bool = False


@dataclass
class PreprocessResult:
    main_file: str
    auxiliary_files: list[str]
    slither_used: bool
    fallback_used: bool
    warnings: list[str]
    findings: list[StaticFinding]
    static_summary: str
    cropped_context: str
    source_bundle: list[SourceUnit]

    def to_dict(self) -> dict:
        return {
            "main_file": self.main_file,
            "auxiliary_files": self.auxiliary_files,
            "slither_used": self.slither_used,
            "fallback_used": self.fallback_used,
            "warnings": self.warnings,
            "findings": [asdict(item) for item in self.findings],
            "static_summary": self.static_summary,
            "cropped_context": self.cropped_context,
            "source_bundle": [asdict(item) for item in self.source_bundle],
        }


def preprocess_contract(
    main_file: Path | str,
    auxiliary_files: Sequence[Path | str] | None = None,
) -> PreprocessResult:
    main_path = Path(main_file).resolve()
    aux_paths = [Path(path).resolve() for path in (auxiliary_files or [])]
    source_bundle = [
        SourceUnit(path=str(main_path), content=main_path.read_text(encoding="utf-8"))
    ]
    source_bundle.extend(
        SourceUnit(path=str(path), content=path.read_text(encoding="utf-8"))
        for path in aux_paths
    )

    warnings: list[str] = []
    findings: list[StaticFinding] = []
    slither_used = False
    fallback_used = False

    if Slither is not None:
        try:
            findings = _collect_slither_findings(main_path)
            slither_used = True
        except Exception as exc:  # pragma: no cover - runtime environment specific
            warnings.append(f"Slither unavailable for {main_path.name}: {exc}")

    if not findings:
        findings = _collect_heuristic_findings(main_path)
        fallback_used = True
        if not findings:
            warnings.append(
                "No risky function was identified; the full main contract is kept as context."
            )

    static_summary = _build_static_summary(main_path, aux_paths, findings, warnings)
    cropped_context = _build_cropped_context(source_bundle, findings)

    return PreprocessResult(
        main_file=str(main_path),
        auxiliary_files=[str(path) for path in aux_paths],
        slither_used=slither_used,
        fallback_used=fallback_used,
        warnings=warnings,
        findings=findings,
        static_summary=static_summary,
        cropped_context=cropped_context,
        source_bundle=source_bundle,
    )


def write_preprocess_result(result: PreprocessResult, output_path: Path | str) -> None:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _collect_slither_findings(main_path: Path) -> list[StaticFinding]:
    slither = Slither(str(main_path))
    findings: list[StaticFinding] = []
    for contract in getattr(slither, "contracts", []):
        for function in getattr(contract, "functions", []):
            if getattr(function, "is_constructor", False):
                continue

            can_send_eth = _safe_bool_call(function, "can_send_eth")
            external_calls = _normalize_external_calls(function)
            if not can_send_eth and not external_calls:
                continue

            source_code = _extract_source_code(getattr(function, "source_mapping", None))
            state_reads = _extract_state_var_names(
                getattr(function, "state_variables_read", [])
            )
            state_writes = _extract_state_var_names(
                getattr(function, "state_variables_written", [])
            )
            reasons: list[str] = []
            if can_send_eth:
                reasons.append("can_send_eth")
            if external_calls:
                reasons.append("external_calls")

            findings.append(
                StaticFinding(
                    contract_name=getattr(contract, "name", "UnknownContract"),
                    symbol_name=getattr(function, "name", "anonymous"),
                    symbol_type="function",
                    source_code=source_code,
                    reasons=reasons,
                    external_calls=external_calls,
                    state_reads=state_reads,
                    state_writes=state_writes,
                    can_send_eth=can_send_eth,
                    post_interaction_state_update=_detect_post_interaction_state_update(
                        source_code,
                        state_writes,
                    ),
                )
            )
    return findings


def _collect_heuristic_findings(main_path: Path) -> list[StaticFinding]:
    content = main_path.read_text(encoding="utf-8")
    contracts = _extract_contract_blocks(content)
    findings: list[StaticFinding] = []

    for contract_name, contract_source in contracts:
        contract_prelude = _extract_contract_prelude(contract_source)
        modifiers = {
            block["name"]: block["source"]
            for block in _extract_symbol_blocks(contract_source)
            if block["kind"].lower() == "modifier"
        }

        for block in _extract_symbol_blocks(contract_source):
            if block["kind"].lower() == "modifier":
                if _symbol_has_risky_call(block["source"]):
                    findings.append(
                        StaticFinding(
                            contract_name=contract_name,
                            symbol_name=block["name"],
                            symbol_type="modifier",
                            source_code=block["source"],
                            reasons=["external_calls"],
                            external_calls=_extract_external_call_tokens(block["source"]),
                            state_reads=[],
                            state_writes=[],
                            can_send_eth=_symbol_can_send_eth(block["source"]),
                            post_interaction_state_update=False,
                        )
                    )
                continue

            if not _symbol_has_risky_call(block["source"]):
                attached_modifiers = _extract_attached_modifiers(block["signature"])
                related_modifier_sources = [
                    modifiers[name] for name in attached_modifiers if name in modifiers
                ]
                if not any(_symbol_has_risky_call(source) for source in related_modifier_sources):
                    continue
            attached_modifiers = _extract_attached_modifiers(block["signature"])
            related_modifier_sources = [
                modifiers[name] for name in attached_modifiers if name in modifiers
            ]
            combined_source = "\n\n".join([block["source"], *related_modifier_sources]).strip()
            state_writes = _extract_state_write_candidates(contract_prelude, combined_source)
            findings.append(
                StaticFinding(
                    contract_name=contract_name,
                    symbol_name=block["name"],
                    symbol_type=block["kind"].lower(),
                    source_code=combined_source,
                    reasons=_build_heuristic_reasons(combined_source),
                    external_calls=_extract_external_call_tokens(combined_source),
                    state_reads=[],
                    state_writes=state_writes,
                    can_send_eth=_symbol_can_send_eth(combined_source),
                    post_interaction_state_update=_detect_post_interaction_state_update(
                        combined_source,
                        state_writes,
                    ),
                )
            )

    return _deduplicate_findings(findings)


def _build_static_summary(
    main_path: Path,
    aux_paths: Sequence[Path],
    findings: Sequence[StaticFinding],
    warnings: Sequence[str],
) -> str:
    lines = [
        f"主合约文件: {redact_prompt_text(main_path.name)}",
        f"辅助文件数量: {len(aux_paths)}",
        f"识别到的风险符号数量: {len(findings)}",
    ]
    for finding in findings:
        call_text = ", ".join(finding.external_calls) if finding.external_calls else "-"
        write_text = ", ".join(finding.state_writes) if finding.state_writes else "-"
        lines.append(
            " | ".join(
                [
                    f"符号={redact_prompt_text(finding.contract_name)}.{redact_prompt_text(finding.symbol_name)}",
                    f"类型={finding.symbol_type}",
                    f"原因={','.join(finding.reasons) or '-'}",
                    f"ETH发送={finding.can_send_eth}",
                    f"外部调用={call_text}",
                    f"写状态={write_text}",
                    f"交互后更新状态={finding.post_interaction_state_update}",
                ]
            )
        )
    for warning in warnings:
        lines.append(f"警告: {redact_prompt_text(warning)}")
    return "\n".join(lines)


def _build_cropped_context(
    source_bundle: Sequence[SourceUnit],
    findings: Sequence[StaticFinding],
) -> str:
    if not source_bundle:
        return ""

    main_source = source_bundle[0].content
    blocks: list[str] = ["// Main contract source"]
    contract_blocks = _extract_contract_blocks(main_source)

    if findings and contract_blocks:
        contract_name = findings[0].contract_name
        matching_contract = next(
            (source for name, source in contract_blocks if name == contract_name),
            contract_blocks[0][1],
        )
        prelude = _extract_contract_prelude(matching_contract)
        blocks.append(redact_prompt_text(prelude.strip()))

        for finding in findings:
            if finding.source_code.strip():
                blocks.append(f"// Risk-focused slice: {redact_prompt_text(finding.symbol_name)}")
                blocks.append(redact_prompt_text(finding.source_code.strip()))
    else:
        blocks.append(redact_prompt_text(main_source.strip()))

    for index, unit in enumerate(source_bundle[1:], start=1):
        blocks.append(f"// Auxiliary source #{index}")
        blocks.append(redact_prompt_text(unit.content.strip()))

    return "\n\n".join(block for block in blocks if block.strip())


def _extract_source_code(source_mapping: object | None) -> str:
    if source_mapping is None:
        return ""
    content = getattr(source_mapping, "content", "")
    if isinstance(content, str):
        return content
    return ""


def _extract_state_var_names(items: Iterable[object]) -> list[str]:
    result: list[str] = []
    for item in items:
        name = getattr(item, "name", None)
        if isinstance(name, str) and name not in result:
            result.append(name)
    return result


def _normalize_external_calls(function: object) -> list[str]:
    calls: list[str] = []
    for attribute_name in ("high_level_calls", "low_level_calls", "library_calls"):
        values = getattr(function, attribute_name, []) or []
        for value in values:
            call_name = _format_slither_call(value)
            if call_name and call_name not in calls:
                calls.append(call_name)
    return calls


def _format_slither_call(value: object) -> str:
    if isinstance(value, tuple):
        parts = [str(part) for part in value if part is not None]
        return ".".join(parts)
    return str(value)


def _safe_bool_call(instance: object, method_name: str) -> bool:
    method = getattr(instance, method_name, None)
    if callable(method):
        try:
            return bool(method())
        except Exception:
            return False
    return bool(method)


def _extract_contract_blocks(content: str) -> list[tuple[str, str]]:
    pattern = re.compile(
        r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
        re.MULTILINE,
    )
    results: list[tuple[str, str]] = []
    for match in pattern.finditer(content):
        brace_start = content.find("{", match.end())
        if brace_start == -1:
            continue
        brace_end = _find_matching_brace(content, brace_start)
        if brace_end == -1:
            continue
        results.append((match.group(1), content[match.start() : brace_end + 1]))
    return results


def _extract_contract_prelude(contract_source: str) -> str:
    match = FUNCTION_LIKE_PATTERN.search(contract_source)
    if not match:
        return contract_source
    return contract_source[: match.start()].rstrip()


def _extract_symbol_blocks(contract_source: str) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    pattern = re.compile(
        r"^\s*(function|modifier|constructor|fallback|receive)\b\s*([A-Za-z_][A-Za-z0-9_]*)?",
        re.MULTILINE,
    )
    for match in pattern.finditer(contract_source):
        brace_start = contract_source.find("{", match.end())
        if brace_start == -1:
            continue
        signature = contract_source[match.start() : brace_start].strip()
        brace_end = _find_matching_brace(contract_source, brace_start)
        if brace_end == -1:
            continue
        blocks.append(
            {
                "kind": match.group(1),
                "name": match.group(2) or match.group(1),
                "signature": signature,
                "source": contract_source[match.start() : brace_end + 1],
            }
        )
    return blocks


def _find_matching_brace(text: str, opening_index: int) -> int:
    depth = 0
    for index in range(opening_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _symbol_can_send_eth(symbol_source: str) -> bool:
    return any(pattern.search(symbol_source) for pattern in ETH_CALL_PATTERNS)


def _symbol_has_risky_call(symbol_source: str) -> bool:
    if _symbol_can_send_eth(symbol_source):
        return True
    return bool(GENERIC_EXTERNAL_CALL_PATTERN.search(symbol_source))


def _extract_external_call_tokens(symbol_source: str) -> list[str]:
    calls: list[str] = []
    for pattern in ETH_CALL_PATTERNS:
        if pattern.search(symbol_source):
            token = pattern.pattern.replace("\\", "")
            if token not in calls:
                calls.append(token)
    for match in GENERIC_EXTERNAL_CALL_PATTERN.finditer(symbol_source):
        token = match.group(0).strip()
        if token not in calls:
            calls.append(token)
    return calls[:10]


def _extract_attached_modifiers(signature: str) -> list[str]:
    candidates = MODIFIER_NAME_PATTERN.findall(signature)
    ignored = {
        "function",
        "constructor",
        "fallback",
        "receive",
        "returns",
        "if",
        "while",
        "for",
    }
    result: list[str] = []
    for candidate in candidates:
        if candidate in ignored:
            continue
        if candidate not in result:
            result.append(candidate)
    return result


def _extract_state_write_candidates(contract_prelude: str, symbol_source: str) -> list[str]:
    declarations = _extract_declared_state_names(contract_prelude)
    writes = []
    for candidate in declarations:
        if re.search(rf"\b{re.escape(candidate)}\b", symbol_source):
            writes.append(candidate)
    for match in ASSIGNMENT_PATTERN.finditer(symbol_source):
        name = match.group(1)
        if name not in writes:
            writes.append(name)
    return writes[:10]


def _extract_declared_state_names(contract_prelude: str) -> list[str]:
    results: list[str] = []
    for line in contract_prelude.splitlines():
        stripped = line.strip().rstrip(";")
        if not stripped or stripped.startswith("//"):
            continue
        if any(
            stripped.startswith(prefix)
            for prefix in ("pragma ", "import ", "contract ", "interface ", "library ")
        ):
            continue
        tokens = re.split(r"\s+", stripped)
        if len(tokens) < 2:
            continue
        last_token = tokens[-1]
        last_token = last_token.split("=")[0].strip()
        if last_token.isidentifier() and last_token not in results:
            results.append(last_token)
    return results


def _build_heuristic_reasons(source: str) -> list[str]:
    reasons: list[str] = []
    if _symbol_can_send_eth(source):
        reasons.append("can_send_eth")
    if GENERIC_EXTERNAL_CALL_PATTERN.search(source):
        reasons.append("external_calls")
    return reasons or ["heuristic_risk"]


def _detect_post_interaction_state_update(source: str, state_vars: Sequence[str]) -> bool:
    interaction_index = _find_first_interaction_index(source)
    if interaction_index == -1:
        return False

    tail = source[interaction_index:]
    for state_var in state_vars:
        if re.search(rf"\b{re.escape(state_var)}\b", tail) and re.search(
            rf"\b{re.escape(state_var)}\b\s*(?:\[[^\]]+\])?\s*(?:\+|-|\*|/)?=",
            tail,
        ):
            return True
    return False


def _find_first_interaction_index(source: str) -> int:
    indices = [
        match.start()
        for pattern in (*ETH_CALL_PATTERNS, GENERIC_EXTERNAL_CALL_PATTERN)
        for match in pattern.finditer(source)
    ]
    return min(indices) if indices else -1


def _deduplicate_findings(findings: Sequence[StaticFinding]) -> list[StaticFinding]:
    seen: set[tuple[str, str, str]] = set()
    result: list[StaticFinding] = []
    for finding in findings:
        key = (finding.contract_name, finding.symbol_name, finding.symbol_type)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result
