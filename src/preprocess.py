from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

try:
    from slither import Slither  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Slither = None

# solc-select 二进制路径映射，用于自动匹配合约的 pragma 版本
_SOLC_BINARIES: dict[str, str] = {}
_solc_artifacts = Path.home() / ".solc-select" / "artifacts"
if _solc_artifacts.exists():
    for _d in _solc_artifacts.iterdir():
        if _d.is_dir():
            _ver = _d.name.replace("solc-", "")
            _bin = _d / f"solc-{_ver}"
            if _bin.exists():
                _SOLC_BINARIES[_ver] = str(_bin)


ETH_CALL_PATTERNS = (
    re.compile(r"\.call\s*\{", re.IGNORECASE),
    re.compile(r"\.call\s*\(", re.IGNORECASE),
    re.compile(r"\.transfer\s*\(", re.IGNORECASE),
    re.compile(r"\.send\s*\(", re.IGNORECASE),
)
REENTRANCY_CALL_PATTERNS = (
    re.compile(r"\.call\s*\{", re.IGNORECASE),
    re.compile(r"\.call\s*\(", re.IGNORECASE),
    re.compile(r"\.delegatecall\s*\(", re.IGNORECASE),
    re.compile(r"\.callcode\s*\(", re.IGNORECASE),
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
    slice_mode: str = "risk",
    slice_max_chars: int = 3800,
    slice_min_lines: int = 5,
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
    cropped_context = _build_cropped_context(
        source_bundle,
        findings,
        slice_mode=slice_mode,
        slice_max_chars=slice_max_chars,
        slice_min_lines=slice_min_lines,
    )

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


def _detect_solc_binary(main_path: Path) -> str:
    """根据合约 pragma 版本自动匹配 solc 二进制路径。"""
    try:
        content = main_path.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r'pragma\s+solidity\s+[\^~>=]*\s*(\d+\.\d+\.\d+)', content)
        if m:
            req_ver = m.group(1)
            # 精确匹配
            if req_ver in _SOLC_BINARIES:
                return _SOLC_BINARIES[req_ver]
            # 同主版本号兼容匹配（如 ^0.4.19 匹配 0.4.26）
            major_minor = ".".join(req_ver.split(".")[:2])
            candidates = sorted(
                [(v, b) for v, b in _SOLC_BINARIES.items() if v.startswith(major_minor)],
                key=lambda x: x[0], reverse=True
            )
            if candidates:
                return candidates[0][1]  # 取最新兼容版本
    except Exception:
        pass
    return "solc"


def _collect_slither_findings(main_path: Path) -> list[StaticFinding]:
    # 自动检测合约 pragma 版本，匹配对应的 solc 二进制
    solc_binary = _detect_solc_binary(main_path)

    slither = Slither(str(main_path), solc=solc_binary)
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
    slice_mode: str = "risk",
    slice_max_chars: int = 3800,
    slice_min_lines: int = 5,
) -> str:
    if slice_mode == "reentrancy_slice_v1":
        # 尝试从缓存目录加载预计算切片
        cached = _try_load_slice_cache(source_bundle)
        if cached is not None:
            return cached
        return _build_reentrancy_slice_context(
            source_bundle,
            slice_max_chars=slice_max_chars,
            slice_min_lines=slice_min_lines,
        )

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


def _strip_comments(source: str) -> str:
    source = re.sub(r"/\*[\s\S]*?\*/", "", source)
    cleaned_lines: list[str] = []
    for line in source.splitlines():
        if "//" in line:
            line = line.split("//", 1)[0]
        if line.strip():
            cleaned_lines.append(line.rstrip())
    return "\n".join(cleaned_lines)


def _clean_prelude(prelude: str) -> str:
    cleaned = _strip_comments(prelude)
    filtered: list[str] = []
    for line in cleaned.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("pragma "):
            continue
        if stripped.startswith("import "):
            continue
        filtered.append(line.rstrip())
    return "\n".join(filtered)


def _count_effective_lines(source: str) -> int:
    return len([line for line in source.splitlines() if line.strip()])


def _symbol_has_reentrancy_call(symbol_source: str) -> bool:
    return any(pattern.search(symbol_source) for pattern in REENTRANCY_CALL_PATTERNS)


# ---------------------------------------------------------------------------
# 规则 3 辅助：module-level 全局统计缓存
# ---------------------------------------------------------------------------

_GLOBAL_STATS_CACHE: dict[str, object] | None = None
_GLOBAL_STATS_LOADED: bool = False


def _load_global_stats() -> dict[str, object] | None:
    """从 contracts_reentrancy_slice_v1/global_stats.json 加载预计算全局统计"""
    global _GLOBAL_STATS_CACHE, _GLOBAL_STATS_LOADED
    if _GLOBAL_STATS_LOADED:
        return _GLOBAL_STATS_CACHE
    _GLOBAL_STATS_LOADED = True

    # 尝试多个可能位置
    candidates = [
        Path(__file__).resolve().parent.parent / "contracts_reentrancy_slice_v1" / "global_stats.json",
    ]
    for path in candidates:
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                _GLOBAL_STATS_CACHE = data
                return data
            except Exception:
                continue
    return None


def _is_significant_name(func_name: str, global_stats: dict[str, object] | None) -> bool:
    if global_stats is None:
        return False
    significant_names = global_stats.get("significant_names", [])
    return func_name in significant_names


def _try_load_slice_cache(source_bundle: Sequence[SourceUnit]) -> str | None:
    """
    尝试从 contracts_reentrancy_slice_v1/ 目录加载预计算切片。
    匹配规则：根据主文件名匹配 sample_id。
    返回 None 若缓存未命中。
    """
    if not source_bundle:
        return None
    main_file_name = Path(source_bundle[0].path).name

    slice_root = Path(__file__).resolve().parent.parent / "contracts_reentrancy_slice_v1"
    if not slice_root.exists():
        return None

    manifest_path = slice_root / "slice_manifest.json"
    if not manifest_path.exists():
        return None

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    for entry in manifest:
        # 按主文件名匹配
        contract_names = entry.get("contract_name", "")
        if "," in contract_names:
            names = [n.strip() for n in contract_names.split(",")]
        else:
            names = [contract_names.strip()]

        # 如果合约名是主文件名的一部分（去掉 .sol），则匹配
        main_stem = Path(source_bundle[0].path).stem
        if any(name in main_stem or main_stem in name for name in names):
            sample_dir = slice_root / entry["sample_id"]
            slice_file = sample_dir / "slice.sol"
            if slice_file.exists() and entry.get("has_slice"):
                return slice_file.read_text(encoding="utf-8")

    return None


def _build_reentrancy_slice_context(
    source_bundle: Sequence[SourceUnit],
    slice_max_chars: int,
    slice_min_lines: int,
) -> str:
    """
    规则 1-4 的重入切片引擎。

    改进点 (vs 旧版):
      - 规则1: 只用 REENTRANCY_CALL_PATTERNS（低级call/delegatecall等），不包含 ERC20 transfer
      - 规则2: 保留 LOC>=5 或 含重入调用 的函数 + 被引用的 modifier
      - 规则3: 使用全局显著函数统计（若缓存可用）过滤非关键合约
      - 规则4: 清理注释/import/pragma，转账函数优先，贪心到3800上限
    """
    if not source_bundle:
        return ""

    global_stats = _load_global_stats()

    main_source = source_bundle[0].content
    blocks: list[str] = ["// Reentrancy slice v1"]
    total_chars = 0

    contract_blocks = _extract_contract_blocks(main_source)
    if not contract_blocks:
        cleaned = _strip_comments(main_source)
        return cleaned.strip()

    # 预扫描：检测 ReentrancyGuard 类父合约
    guard_modifiers: dict[str, str] = {}  # parent_name → modifier source
    for c_name, c_source in contract_blocks:
        # 解析 modifier 定义
        symbol_blocks = _extract_symbol_blocks(c_source)
        for block in symbol_blocks:
            if block["kind"].lower() == "modifier" and block["name"].lower() in ("nonreentrant", "noreentrant"):
                guard_modifiers[c_name] = _strip_comments(block["source"])
                break

    for contract_name, contract_source in contract_blocks:
        prelude_raw = _extract_contract_prelude(contract_source)
        prelude = _clean_prelude(prelude_raw)

        symbol_blocks = _extract_symbol_blocks(contract_source)
        modifiers = {
            block["name"]: block["source"]
            for block in symbol_blocks
            if block["kind"].lower() == "modifier"
        }

        # 收集函数元信息
        func_metas: list[dict[str, object]] = []
        has_any_reentrancy = False
        has_any_significant = False

        for block in symbol_blocks:
            if block["kind"].lower() == "modifier":
                continue
            signature = block["signature"]
            attached_modifiers = _extract_attached_modifiers(signature)
            related_modifier_sources = [
                modifiers[name] for name in attached_modifiers if name in modifiers
            ]
            combined_source = "\n\n".join([block["source"], *related_modifier_sources]).strip()
            cleaned_source = _strip_comments(combined_source)
            if not cleaned_source.strip():
                continue
            line_count = _count_effective_lines(cleaned_source)
            has_reentrancy_call = _symbol_has_reentrancy_call(combined_source)
            is_significant = _is_significant_name(block.get("name", ""), global_stats)

            if has_reentrancy_call:
                has_any_reentrancy = True
            if is_significant:
                has_any_significant = True

            func_metas.append({
                "contract": contract_name,
                "name": block["name"],
                "kind": block["kind"].lower(),
                "signature": signature,
                "source": cleaned_source,
                "line_count": line_count,
                "char_len": len(cleaned_source),
                "has_reentrancy_call": has_reentrancy_call,
                "is_significant": is_significant,
                "attached_modifiers": attached_modifiers,
            })

        # 规则3 合约保留规则：包含显著函数或外部调用函数才保留
        if global_stats and not has_any_reentrancy and not has_any_significant:
            continue

        # 输出 prelude
        if prelude:
            blocks.append("// Contract prelude")
            blocks.append(prelude)
            total_chars += len(prelude)

        # 安全上下文注入：检测 nonReentrant 使用
        if guard_modifiers:
            uses_guard = any(
                m.lower() in ("nonreentrant", "noreentrant")
                for item in func_metas
                for m in item.get("attached_modifiers", [])
            )
            if uses_guard:
                # 查找继承的父合约
                import re as _re
                decl = _re.search(r'contract\s+\w+\s+is\s+(\w+)', contract_source, _re.I)
                if decl:
                    parent = decl.group(1)
                    guard_src = guard_modifiers.get(parent, "")
                    if guard_src:
                        blocks.append(
                            "// [guard] nonReentrant 修饰符（重入保护锁）："
                            "在执行函数体之前设置 locked=true，阻止回调重入"
                        )
                        blocks.append(guard_src)
                        total_chars += len(guard_src)

        # 规则2: 函数筛选 - LOC>=5 或 含重入调用
        must_keep = [
            item for item in func_metas
            if item["has_reentrancy_call"]
        ]
        optional = [
            item for item in func_metas
            if not item["has_reentrancy_call"] and int(item["line_count"]) >= slice_min_lines
        ]

        # 收集被保留函数引用的 modifier
        kept_modifier_names: set[str] = set()
        for item in must_keep + optional:
            for mod_name in item.get("attached_modifiers", []):
                if mod_name in modifiers:
                    kept_modifier_names.add(mod_name)

        must_keep.sort(key=lambda item: int(item["char_len"]), reverse=True)
        optional.sort(key=lambda item: int(item["char_len"]), reverse=True)

        def _projected(header: str, source: str) -> int:
            return total_chars + len(header) + len(source)

        def _add_block(header: str, source: str, force: bool) -> bool:
            nonlocal total_chars
            proj = _projected(header, source)
            if not force and proj > slice_max_chars:
                return False
            blocks.append(header)
            blocks.append(source)
            total_chars = proj
            return True

        # 优先级1: 转账/外部调用函数（强制保留）
        for item in must_keep:
            tag = "reentrancy-call"
            if int(item["line_count"]) < slice_min_lines:
                tag = "short-keep"
            header = f"// [{tag}] {item['name']}"
            _add_block(header, str(item["source"]).strip(), force=True)

            # 附加其 modifier
            for mod_name in item.get("attached_modifiers", []):
                if mod_name in modifiers and mod_name in kept_modifier_names:
                    mod_source = _strip_comments(modifiers[mod_name])
                    if not mod_source.strip():
                        continue
                    mod_header = f"// [modifier] {mod_name}"
                    if _projected(mod_header, mod_source) > slice_max_chars:
                        continue
                    _add_block(mod_header, mod_source, force=False)

        # 优先级2: 其他长度>=5的函数，贪心补齐
        for item in optional:
            header = f"// [context] {item['name']}"
            if not _add_block(header, str(item["source"]).strip(), force=False):
                break

            for mod_name in item.get("attached_modifiers", []):
                if mod_name in modifiers and mod_name in kept_modifier_names:
                    mod_source = _strip_comments(modifiers[mod_name])
                    if not mod_source.strip():
                        continue
                    mod_header = f"// [modifier] {mod_name}"
                    if _projected(mod_header, mod_source) > slice_max_chars:
                        continue
                    _add_block(mod_header, mod_source, force=False)

    # 辅助源文件按需拼接
    for index, unit in enumerate(source_bundle[1:], start=1):
        cleaned_aux = _strip_comments(unit.content)
        if not cleaned_aux.strip():
            continue
        header = f"// Auxiliary source #{index}"
        projected = total_chars + len(header) + len(cleaned_aux)
        if projected > slice_max_chars:
            break
        blocks.append(header)
        blocks.append(cleaned_aux)
        total_chars = projected

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
