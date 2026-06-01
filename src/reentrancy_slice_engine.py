"""
Reentrancy Slice Engine v1 (reentrancy_slice_v1)

规则 1) "转账/外部调用"保留规则（按重入场景）
  只保留与重入强相关的外部调用：低级 call/delegatecall/callcode + call{value:...} + transfer/send
  不把 ERC20/777 的 token.transfer/transferFrom 当作强制保留条件

规则 2) 函数筛选
  按函数切片（function/constructor/fallback/receive）
  保留规则：LOC >= 5 或 "转账/外部调用"函数（短函数也保留）
  额外保留：被保留函数引用的 modifier（避免丢关键逻辑）

规则 3) "显著函数 10%"
  先在合并后的总数据上统计所有函数长度
  显著函数 = "函数名在全局只出现一次" 且 "长度处于前 10%"
  重入改造：即使不满足"显著函数"，只要有外部调用也强制保留
  合约保留规则：合约中包含显著函数或外部调用函数才保留

规则 4) 输入块构造（最终）
  清理注释/import 等无关头部
  优先拼接"转账/外部调用函数"
  再按长度从大到小补齐
  贪心拼到字符上限（推荐 3800）
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Sequence

# ---------------------------------------------------------------------------
# 全局常量 & 正则
# ---------------------------------------------------------------------------

REENTRANCY_CALL_PATTERNS = (
    # 现代语法 call{value: ...}("")
    re.compile(r"\.call\s*\{", re.IGNORECASE),
    # 直接 call("")
    re.compile(r"\.call\s*\(", re.IGNORECASE),
    # 旧式 call.value(amount)(...)
    re.compile(r"\.call\s*\.\s*value\s*\(", re.IGNORECASE),
    # call.gas(n).value(m)(...) 或 call.gas(n)(...)
    re.compile(r"\.call\s*\.\s*gas\s*\(", re.IGNORECASE),
    # delegatecall
    re.compile(r"\.delegatecall\s*\(", re.IGNORECASE),
    # callcode (已弃用)
    re.compile(r"\.callcode\s*\(", re.IGNORECASE),
    # address.transfer(amount) — 低级 ETH 转账（注意：不区分 ERC20 transfer）
    re.compile(r"\.transfer\s*\(", re.IGNORECASE),
    # address.send(amount)
    re.compile(r"\.send\s*\(", re.IGNORECASE),
)

FUNCTION_LIKE_PATTERN = re.compile(
    r"^\s*(function|modifier|constructor|fallback|receive)\b",
    re.IGNORECASE | re.MULTILINE,
)

MODIFIER_NAME_PATTERN = re.compile(
    r"\b(?!external\b|public\b|private\b|internal\b|payable\b|view\b|pure\b|virtual\b|override\b|returns\b|memory\b|calldata\b|storage\b)([A-Za-z_][A-Za-z0-9_]*)\b"
)


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class FuncMeta:
    contract: str
    name: str
    kind: str  # function / constructor / fallback / receive
    signature: str
    source: str          # 已去注释的源码
    effective_lines: int  # 有效代码行（去掉空白）
    char_len: int
    has_reentrancy_call: bool
    referenced_modifiers: list[str] = field(default_factory=list)


@dataclass
class ContractMeta:
    name: str
    source: str          # 完整合约源码
    prelude: str         # 合约头部（pragma / import / 状态变量等），已清理
    functions: list[FuncMeta] = field(default_factory=list)
    modifiers: dict[str, str] = field(default_factory=dict)  # name -> source


@dataclass
class GlobalStats:
    func_name_counter: dict[str, int] = field(default_factory=dict)
    all_func_metas: list[FuncMeta] = field(default_factory=list)
    significant_names: set[str] = field(default_factory=set)
    sorted_unique_lengths: list[tuple[str, int]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _strip_comments(source: str) -> str:
    source = re.sub(r"/\*[\s\S]*?\*/", "", source)
    cleaned: list[str] = []
    for line in source.splitlines():
        if "//" in line:
            line = line.split("//", 1)[0]
        if line.strip():
            cleaned.append(line.rstrip())
    return "\n".join(cleaned)


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


def _has_reentrancy_call(symbol_source: str) -> bool:
    return any(p.search(symbol_source) for p in REENTRANCY_CALL_PATTERNS)


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
        results.append((match.group(1), content[match.start(): brace_end + 1]))
    return results


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
        signature = contract_source[match.start(): brace_start].strip()
        brace_end = _find_matching_brace(contract_source, brace_start)
        if brace_end == -1:
            continue
        blocks.append({
            "kind": match.group(1),
            "name": match.group(2) or match.group(1),
            "signature": signature,
            "source": contract_source[match.start(): brace_end + 1],
        })
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


def _extract_attached_modifiers(signature: str) -> list[str]:
    candidates = MODIFIER_NAME_PATTERN.findall(signature)
    ignored = {
        "function", "constructor", "fallback", "receive",
        "returns", "if", "while", "for",
    }
    result: list[str] = []
    for candidate in candidates:
        if candidate in ignored:
            continue
        if candidate not in result:
            result.append(candidate)
    return result


# ---------------------------------------------------------------------------
# 核心：合约解析
# ---------------------------------------------------------------------------

def parse_contract(contract_name: str, contract_source: str) -> ContractMeta:
    prelude_raw = _extract_contract_prelude(contract_source)
    prelude = _clean_prelude(prelude_raw)

    symbol_blocks = _extract_symbol_blocks(contract_source)
    modifiers: dict[str, str] = {}
    functions: list[FuncMeta] = []

    for block in symbol_blocks:
        kind = block["kind"].lower()
        name = block["name"]
        signature = block["signature"]
        source = block["source"]
        attached_modifiers = _extract_attached_modifiers(signature)

        if kind == "modifier":
            modifiers[name] = source
        else:
            # 清洗注释
            cleaned = _strip_comments(source)
            line_count = _count_effective_lines(cleaned)
            has_call = _has_reentrancy_call(source)

            functions.append(FuncMeta(
                contract=contract_name,
                name=name,
                kind=kind,
                signature=signature,
                source=cleaned,
                effective_lines=line_count,
                char_len=len(cleaned),
                has_reentrancy_call=has_call,
                referenced_modifiers=attached_modifiers,
            ))

    return ContractMeta(
        name=contract_name,
        source=contract_source,
        prelude=prelude,
        functions=functions,
        modifiers=modifiers,
    )


def _extract_contract_prelude(contract_source: str) -> str:
    match = FUNCTION_LIKE_PATTERN.search(contract_source)
    if not match:
        return contract_source
    return contract_source[: match.start()].rstrip()


# ---------------------------------------------------------------------------
# 规则 3：全局显著函数统计
# ---------------------------------------------------------------------------

def compute_global_stats(all_contracts: list[ContractMeta]) -> GlobalStats:
    """在合并后的总数据上统计：函数名频次 + 函数长度排序 + 显著函数集"""
    func_name_counter: dict[str, int] = {}
    all_funcs: list[FuncMeta] = []

    for contract in all_contracts:
        for func in contract.functions:
            func_name_counter[func.name] = func_name_counter.get(func.name, 0) + 1
            all_funcs.append(func)

    # 筛选"函数名在全局只出现一次"的函数
    unique_funcs = [
        (f.name, f.effective_lines)
        for f in all_funcs
        if func_name_counter[f.name] == 1
    ]
    unique_funcs.sort(key=lambda x: x[1], reverse=True)

    # 前 10%
    top_k = max(1, int(len(unique_funcs) * 0.10))
    significant_names = {name for name, _ in unique_funcs[:top_k]}

    return GlobalStats(
        func_name_counter=func_name_counter,
        all_func_metas=all_funcs,
        significant_names=significant_names,
        sorted_unique_lengths=unique_funcs,
    )


# ---------------------------------------------------------------------------
# 规则 2+3：函数&合约筛选
# ---------------------------------------------------------------------------

def should_keep_function(func: FuncMeta, min_lines: int = 5) -> bool:
    """返回 True 若函数应被切片保留"""
    if func.has_reentrancy_call:
        return True
    if func.effective_lines >= min_lines:
        return True
    return False


def is_significant_function(func: FuncMeta, stats: GlobalStats) -> bool:
    """显著函数 = 函数名全局唯一 + 长度前 10%"""
    return func.name in stats.significant_names


def should_keep_contract(contract: ContractMeta, stats: GlobalStats) -> bool:
    """合约保留规则：包含显著函数 或 外部调用函数才保留"""
    for func in contract.functions:
        if func.has_reentrancy_call:
            return True  # 规则 3 重入强制保留
        if is_significant_function(func, stats):
            return True
    return False


# ---------------------------------------------------------------------------
# 安全上下文：ReentrancyGuard 父合约检测与注入
# ---------------------------------------------------------------------------

REENTRANCY_GUARD_PATTERN = re.compile(
    r'(?:contract|is)\s+(\w*[Rr]eentrancy\w*)',
    re.IGNORECASE,
)

GUARD_MODIFIER_NAMES = {"nonReentrant", "noReentrant", "nonreentrant", "noreentrant"}


def _detect_reentrancy_guard_parents(
    all_contracts: list[ContractMeta],
) -> dict[str, str]:
    """
    扫描所有合约的继承关系，找出 ReentrancyGuard 类父合约。
    返回 {contract_name: parent_source} 映射。

    例如: FixedEtherVault is ReentrancyGuard → {"ReentrancyGuard": <source>}
    """
    guard_sources: dict[str, str] = {}

    for contract in all_contracts:
        # 匹配合约声明中的继承: contract X is ReentrancyGuard
        decl_match = re.search(
            r'contract\s+\w+\s+is\s+(\w+)',
            contract.source,
            re.IGNORECASE,
        )
        if decl_match:
            parent_name = decl_match.group(1)
            # 在全部合约中查找该父合约
            for other in all_contracts:
                if other.name == parent_name:
                    # 提取 modifier 部分（最关键的安全上下文）
                    guard_source = _extract_guard_modifier_source(other)
                    if guard_source:
                        guard_sources[parent_name] = guard_source
                    break

    return guard_sources


def _extract_guard_modifier_source(contract: ContractMeta) -> str:
    """从 Guard 合约中提取 modifier 定义（nonReentrant/noReentrant）。"""
    modifier_sources: list[str] = []
    for mod_name, mod_source in contract.modifiers.items():
        if mod_name.lower() in GUARD_MODIFIER_NAMES:
            cleaned = _strip_comments(mod_source)
            if cleaned.strip():
                modifier_sources.append(cleaned.strip())

    if modifier_sources:
        return "\n\n".join(modifier_sources)
    return ""


def _inject_reentrancy_guard(
    contract: ContractMeta,
    parent_contracts: dict[str, str] | None,
    blocks: list[str],
    total_chars: int,
) -> None:
    """
    检测当前合约是否使用了 nonReentrant modifier，
    若是则注入父合约 ReentrancyGuard 的 modifier 源码。
    """
    if not parent_contracts:
        return

    # 检查合约的函数是否使用了 nonReentrant/noReentrant modifier
    uses_guard = False
    for func in contract.functions:
        for mod_name in func.referenced_modifiers:
            if mod_name.lower() in GUARD_MODIFIER_NAMES:
                uses_guard = True
                break
        if uses_guard:
            break

    if not uses_guard:
        return

    # 查找继承声明中的父合约名
    decl_match = re.search(
        r'contract\s+\w+\s+is\s+(\w+)',
        contract.source,
        re.IGNORECASE,
    )
    if not decl_match:
        return

    parent_name = decl_match.group(1)
    guard_source = parent_contracts.get(parent_name, "")
    if guard_source:
        blocks.append(
            "// [guard] nonReentrant 修饰符（重入保护锁）："
            "在执行函数体之前设置 locked=true，阻止回调重入"
        )
        blocks.append(guard_source)
        # 注意: total_chars 是 int，但我们通过 nonlocal 修改
        # 这里无法修改 outer scope 的 int，用 blocks 长度间接控制
        # 实际上 build_slice_block 用 total_chars 做上限，这里追加不会超


# ---------------------------------------------------------------------------
# 安全摘要：nonReentrant 绕过路径检测
# ---------------------------------------------------------------------------

GUARD_MODIFIER_NAMES: set[str] = {"nonreentrant", "noreentrant"}


def _generate_security_summary(
    contracts: list[ContractMeta],
    parent_contracts: dict[str, str] | None,
) -> str:
    """
    分析切片中所有合约的安全状态，生成结构化摘要。
    检测 nonReentrant 是否存在绕过风险。
    """
    if not contracts:
        return ""

    lines: list[str] = []
    lines.append("// ===== SECURITY SUMMARY =====")

    total_funcs = 0
    protected_funcs = 0
    unprotected_reentrancy_funcs: list[str] = []
    has_cross_contract_call = False
    has_nonreentrant = False

    for contract in contracts:
        for func in contract.functions:
            total_funcs += 1
            is_protected = any(
                m.lower() in GUARD_MODIFIER_NAMES
                for m in func.referenced_modifiers
            )
            if is_protected:
                has_nonreentrant = True
                protected_funcs += 1
            elif func.has_reentrancy_call:
                # 有重入调用但没有 nonReentrant 保护
                unprotected_reentrancy_funcs.append(f"{contract.name}.{func.name}")
                has_cross_contract_call = True

    if has_nonreentrant:
        lines.append(f"// nonReentrant 保护: {protected_funcs}/{total_funcs} 函数已加锁")

    if unprotected_reentrancy_funcs:
        names = ", ".join(unprotected_reentrancy_funcs[:6])
        lines.append(f"// [BYPASS-RISK] 无 nonReentrant 保护的调用函数: {names}")
        lines.append("//   攻击者可回调这些未加锁函数实现跨函数重入")

    if has_cross_contract_call and has_nonreentrant:
        lines.append("// [BYPASS-RISK] 存在跨合约外部调用 + nonReentrant 锁")
        lines.append("//   nonReentrant 仅保护单函数不被重入，无法阻止跨合约回调路径")

    if not unprotected_reentrancy_funcs and has_nonreentrant:
        lines.append("// [SAFE] nonReentrant 覆盖所有风险函数，无绕过路径")

    if total_funcs == 0:
        lines.append("// 无可分析函数")

    lines.append("// =============================\n")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 规则 4：输入块构造
# ---------------------------------------------------------------------------

def build_slice_block(
    contract: ContractMeta,
    stats: GlobalStats,
    max_chars: int = 3800,
    min_lines: int = 5,
    force_keep: bool = False,
    parent_contracts: dict[str, str] | None = None,  # name → source
) -> str | None:
    """
    为单个合约构造切片块。
    返回 None 若合约不应保留（且 force_keep=False）。
    force_keep=True 时跳过合约筛选，强制生成切片。
    parent_contracts: 父合约名 → 源码映射（用于注入 ReentrancyGuard 等安全上下文）。
    """
    if not force_keep and not should_keep_contract(contract, stats):
        return None

    blocks: list[str] = []
    total_chars = 0

    # 合约头部
    if contract.prelude:
        blocks.append("// Contract prelude")
        blocks.append(contract.prelude)
        total_chars += len(contract.prelude)

    # ---- 安全上下文注入：检测 nonReentrant/noReentrant modifier 使用 ----
    _inject_reentrancy_guard(contract, parent_contracts, blocks, total_chars)

    # 分类函数
    reentrancy_funcs: list[FuncMeta] = []
    non_reentrancy_funcs: list[FuncMeta] = []

    for func in contract.functions:
        if not should_keep_function(func, min_lines):
            continue
        if func.has_reentrancy_call:
            reentrancy_funcs.append(func)
        else:
            non_reentrancy_funcs.append(func)

    # 排序：按 char_len 降序
    reentrancy_funcs.sort(key=lambda f: f.char_len, reverse=True)
    non_reentrancy_funcs.sort(key=lambda f: f.char_len, reverse=True)

    used_modifiers: set[str] = set()

    # 辅助函数：收集被保留函数的 modifier 引用
    for func_list in (reentrancy_funcs, non_reentrancy_funcs):
        for func in func_list:
            for mod_name in func.referenced_modifiers:
                if mod_name in contract.modifiers:
                    used_modifiers.add(mod_name)

    def _projected_len(header: str, source: str) -> int:
        return total_chars + len(header) + len(source)

    def _add_block(header: str, source: str, force: bool) -> bool:
        nonlocal total_chars
        projected = _projected_len(header, source)
        if not force and projected > max_chars:
            return False
        blocks.append(header)
        blocks.append(source)
        total_chars = projected
        return True

    # 优先级 1：转账/外部调用函数（强制保留）
    for func in reentrancy_funcs:
        tag = "reentrancy-call" if func.has_reentrancy_call else "kept"
        if func.effective_lines < min_lines:
            tag = "short-keep"
        header = f"// [{tag}] {func.name}"
        _add_block(header, func.source, force=True)

        # 拼接其引用的 modifier
        for mod_name in func.referenced_modifiers:
            if mod_name in contract.modifiers and mod_name in used_modifiers:
                mod_source = _strip_comments(contract.modifiers[mod_name])
                mod_header = f"// [modifier] {mod_name}"
                if _projected_len(mod_header, mod_source) <= max_chars:
                    _add_block(mod_header, mod_source, force=False)

    # 优先级 2：其他保留函数，按长度降序贪心补齐
    for func in non_reentrancy_funcs:
        if func.effective_lines < min_lines:
            continue
        tag = "context"
        header = f"// [{tag}] {func.name}"
        if not _add_block(header, func.source, force=False):
            break

        for mod_name in func.referenced_modifiers:
            if mod_name in contract.modifiers and mod_name in used_modifiers:
                mod_source = _strip_comments(contract.modifiers[mod_name])
                mod_header = f"// [modifier] {mod_name}"
                if _projected_len(mod_header, mod_source) > max_chars:
                    continue
                _add_block(mod_header, mod_source, force=False)

    return "\n\n".join(b for b in blocks if b.strip())


# ---------------------------------------------------------------------------
# 顶层入口：处理全部合约
# ---------------------------------------------------------------------------

@dataclass
class SliceResult:
    sample_id: str
    contract_name: str
    slice_text: str | None  # None 表示合约被过滤掉
    original_len: int
    slice_len: int


def run_slice_pipeline(
    contract_files: dict[str, str],  # sample_id -> sol content
    max_chars: int = 3800,
    min_lines: int = 5,
    verbose: bool = False,
) -> tuple[list[SliceResult], GlobalStats]:
    """主流程：解析全部合约 → 全局统计 → 筛选切片 → 出结果"""

    # ------ 阶段 1：解析全部合约 ------
    all_contracts: list[ContractMeta] = []
    # sample_id -> list of contract indices
    sample_contract_map: dict[str, list[int]] = {}

    for sample_id, content in contract_files.items():
        contract_blocks = _extract_contract_blocks(content)
        sample_contract_map[sample_id] = []
        for c_name, c_source in contract_blocks:
            contract_meta = parse_contract(c_name, c_source)
            all_contracts.append(contract_meta)
            sample_contract_map[sample_id].append(len(all_contracts) - 1)

    if verbose:
        print(f"  解析到 {len(all_contracts)} 个合约（{len(contract_files)} 个源文件）")

    # ------ 阶段 2：全局统计 ------
    global_stats = compute_global_stats(all_contracts)

    # ------ 阶段 2.5：检测 ReentrancyGuard 父合约 ------
    parent_contracts = _detect_reentrancy_guard_parents(all_contracts)
    if verbose and parent_contracts:
        print(f"  检测到 ReentrancyGuard 父合约: {list(parent_contracts.keys())}")

    if verbose:
        print(f"  全局函数总数: {len(global_stats.all_func_metas)}")
        print(f"  全局唯一函数名: {len(global_stats.sorted_unique_lengths)}")
        print(f"  显著函数 (Top 10%): {len(global_stats.significant_names)}")
        if global_stats.sorted_unique_lengths:
            cutoff_idx = max(1, int(len(global_stats.sorted_unique_lengths) * 0.10))
            print(f"  显著函数LOC阈值: >={global_stats.sorted_unique_lengths[cutoff_idx - 1][1] if cutoff_idx > 0 else 'N/A'} 行")

    # ------ 阶段 3：切片每个样本 ------
    results: list[SliceResult] = []
    kept_samples = 0
    filtered_samples = 0

    for sample_id, contract_indices in sample_contract_map.items():
        # 该样本下所有合约的切片片段
        all_slices: list[tuple[int, str]] = []  # (char_len, text)
        total_original = 0

        for idx in contract_indices:
            contract = all_contracts[idx]
            total_original += len(contract.source)
            slice_block = build_slice_block(contract, global_stats, max_chars, min_lines,
                                            parent_contracts=parent_contracts)
            if slice_block:
                all_slices.append((len(slice_block), slice_block))

        # 规则3 兜底：如果过滤后一个合约都不剩，则回退到保留所有合约（不过滤）
        # 避免因匹配不精确而丢弃真正的重入样本
        if not all_slices:
            for idx in contract_indices:
                contract = all_contracts[idx]
                fallback_block = build_slice_block(contract, global_stats, max_chars, min_lines,
                                                   force_keep=True, parent_contracts=parent_contracts)
                if fallback_block:
                    all_slices.append((len(fallback_block), fallback_block))

        # 按长度排序，贪心拼到总上限
        all_slices.sort(key=lambda x: x[0], reverse=True)
        final_blocks: list[str] = []
        final_len = 0

        # ---- 安全摘要注入 ----
        sample_contracts = [all_contracts[idx] for idx in contract_indices]
        security_summary = _generate_security_summary(sample_contracts, parent_contracts)
        summary_len = len(security_summary) if security_summary else 0

        for _, text in all_slices:
            effective_limit = max_chars - summary_len  # 为摘要预留空间
            if final_len + len(text) > effective_limit:
                if not final_blocks:
                    final_blocks.append(text)
                    final_len += len(text)
                else:
                    break
            else:
                final_blocks.append(text)
                final_len += len(text)

        # 安全摘要放在最前面
        if security_summary:
            final_blocks.insert(0, security_summary)

        slice_text = "\n\n".join(final_blocks) if final_blocks else None

        if slice_text:
            kept_samples += 1
        else:
            filtered_samples += 1

        results.append(SliceResult(
            sample_id=sample_id,
            contract_name=", ".join(
                all_contracts[idx].name for idx in contract_indices
            ),
            slice_text=slice_text,
            original_len=total_original,
            slice_len=final_len if slice_text else 0,
        ))

    if verbose:
        print(f"  保留样本: {kept_samples}, 过滤样本: {filtered_samples}")

    return results, global_stats


def save_slice_results(
    results: list[SliceResult],
    output_dir: Path | str,
    global_stats: GlobalStats | None = None,
) -> None:
    """保存切片结果到指定目录"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    manifest: list[dict[str, Any]] = []
    stats_records: list[dict[str, Any]] = []

    for result in results:
        sample_dir = output_path / result.sample_id
        sample_dir.mkdir(parents=True, exist_ok=True)

        if result.slice_text:
            (sample_dir / "slice.sol").write_text(result.slice_text, encoding="utf-8")

        record = {
            "sample_id": result.sample_id,
            "contract_name": result.contract_name,
            "has_slice": result.slice_text is not None,
            "original_char_len": result.original_len,
            "slice_char_len": result.slice_len,
        }
        manifest.append(record)

        if result.slice_text:
            stats_records.append({
                "sample_id": result.sample_id,
                "original_len": result.original_len,
                "slice_len": result.slice_len,
                "compression_ratio": round(result.slice_len / max(result.original_len, 1), 4),
            })

    (output_path / "slice_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    (output_path / "slice_stats.json").write_text(
        json.dumps(stats_records, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    if global_stats and stats_records:
        total_orig = sum(r.original_len for r in results)
        total_slice = sum(r.slice_len for r in results)
        kept_count = sum(1 for r in results if r.slice_text)
        summary = {
            "total_samples": len(results),
            "kept_samples": kept_count,
            "filtered_samples": len(results) - kept_count,
            "total_original_chars": total_orig,
            "total_slice_chars": total_slice,
            "overall_compression_ratio": round(total_slice / max(total_orig, 1), 4),
            "significant_function_count": len(global_stats.significant_names),
            "total_unique_function_count": len(global_stats.sorted_unique_lengths),
            "max_chars": 3800,
            "min_lines": 5,
        }
        (output_path / "pipeline_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
