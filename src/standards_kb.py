"""
合约标准知识库：基于 Cai et al. (2025) 的 ERC 标准先验知识。

将合约标准语义注入静态分析摘要，使 LLM 能够：
1. 推断外部调用是否可劫持（hijackable）
2. 识别可利用操作（exploitable operations）类型
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ============================================================
# ERC 标准 → 可劫持外部调用映射（Cai et al. Table I）
# ============================================================

ERC_HIJACKABLE_CALLS: dict[str, list[str]] = {
    "ERC20": [
        # ERC20 标准 transfer 通常不触发 hook，但可能被重写
    ],
    "ERC721": [
        "safeTransferFrom",      # 触发 onERC721Received hook
        "safeBatchTransferFrom", # ERC721A 变体
    ],
    "ERC777": [
        "transfer",             # 触发 tokensToSend / tokensReceived hook
        "transferFrom",         # 同上
        "burn",                 # 触发 tokensToSend hook
        "operatorSend",         # 触发 tokensToSend / tokensReceived hook
    ],
    "ERC1155": [
        "safeTransferFrom",     # 触发 onERC1155Received hook
        "safeBatchTransferFrom", # 同上
    ],
    "ERC1363": [
        "transferAndCall",      # 触发 onTransferReceived hook
        "transferFromAndCall",  # 同上
    ],
}

# 特殊：低级调用的 hook 触发模式
LOW_LEVEL_CALL_HIJACK = [
    "call{value:",        # .call{value: ...}("") - 向 msg.sender 发送 ETH 可触发 fallback
    "call.value(",        # 旧版语法
]

# ============================================================
# 可利用操作识别（Cai et al. Table II 扩展）
# ============================================================

EXPLOITABLE_METHODS: dict[str, list[str]] = {
    # Direct exploitable：将资产直接转移给攻击者的操作
    "direct": [
        ".call{value:",
        ".call.value(",
        ".transfer(",
        ".send(",
        "ERC20.transfer",
        "ERC20.transferFrom",
        "ERC721.safeTransferFrom",
        "ERC777.transfer",
        "ERC777.transferFrom",
    ],
    # Indirect exploitable：操纵直接操作依赖的状态变量
    "indirect_keywords": [
        "delete",           # 删除映射/白名单条目
        "= false",          # 权限标记置 false
        "= 0",              # 余额/计数器清零
        "= true",           # 解锁标记（需上下文判断）
        "-=",               # 余额扣减
    ],
}

# ============================================================
# 合约标准检测
# ============================================================

@dataclass
class ContractStandardInfo:
    """合约标准信息"""
    detected_standards: list[str] = field(default_factory=list)
    hijackable_calls: list[str] = field(default_factory=list)
    has_reentrancy_guard: bool = False
    guard_details: str = ""


def detect_contract_standard(source: str) -> ContractStandardInfo:
    """检测合约遵循的 ERC 标准。

    通过分析合约继承链和接口实现来推断标准类型。
    """
    info = ContractStandardInfo()

    # 方法1：从合约声明中检测继承/接口
    # contract MyToken is ERC20, Ownable { ... }
    contract_decl = re.search(
        r'contract\s+\w+\s+is\s+([^{]+)\{',
        source, re.IGNORECASE
    )
    if contract_decl:
        parents = contract_decl.group(1)
        for std_name in ERC_HIJACKABLE_CALLS:
            if std_name.lower() in parents.lower():
                if std_name not in info.detected_standards:
                    info.detected_standards.append(std_name)

    # 方法2：从 import 路径推断
    for match in re.finditer(r'import\s+["\']([^"\']+)["\']', source):
        path = match.group(1).lower()
        for std_name in ERC_HIJACKABLE_CALLS:
            if std_name.lower() in path:
                if std_name not in info.detected_standards:
                    info.detected_standards.append(std_name)

    # 方法3：从函数签名检测标准接口
    erc721_signatures = [
        r'function\s+safeTransferFrom\s*\(',
        r'function\s+ownerOf\s*\(',
        r'function\s+balanceOf\s*\(',
    ]
    erc777_signatures = [
        r'function\s+operatorSend\s*\(',
        r'function\s+tokensToSend\s*\(',
    ]
    erc1155_signatures = [
        r'function\s+safeBatchTransferFrom\s*\(',
    ]

    if any(re.search(sig, source) for sig in erc721_signatures) or bool(
        re.search(r'interface\s+\w*ERC721\w*', source, re.IGNORECASE)
    ):
        if "ERC721" not in info.detected_standards:
            info.detected_standards.append("ERC721")

    if any(re.search(sig, source) for sig in erc777_signatures) or bool(
        re.search(r'interface\s+\w*ERC777\w*', source, re.IGNORECASE)
    ):
        if "ERC777" not in info.detected_standards:
            info.detected_standards.append("ERC777")

    if any(re.search(sig, source) for sig in erc1155_signatures) or bool(
        re.search(r'interface\s+\w*ERC1155\w*', source, re.IGNORECASE)
    ):
        if "ERC1155" not in info.detected_standards:
            info.detected_standards.append("ERC1155")

    # 检测 ReentrancyGuard
    if re.search(r'ReentrancyGuard|nonReentrant|noReentrant', source, re.IGNORECASE):
        info.has_reentrancy_guard = True
        guard_match = re.search(
            r'modifier\s+(nonReentrant|noReentrant)\s*\([^)]*\)\s*\{',
            source, re.IGNORECASE
        )
        if guard_match:
            info.guard_details = (
                f"{guard_match.group(1)} modifier detected — "
                "执行函数体前 locked=true 上锁，require(!locked) 阻止回调重入"
            )

    return info


def is_external_call_hijackable(
    call_text: str,
    std_info: ContractStandardInfo,
) -> tuple[bool, str]:
    """判断外部调用是否可劫持。

    Returns:
        (is_hijackable, reason)
    """
    # 检查低级调用
    for pattern in LOW_LEVEL_CALL_HIJACK:
        if pattern in call_text:
            return True, "低级调用 call{value:...} — 向 msg.sender 发送 ETH 可触发 fallback/receive 回调"

    # 检查标准定义的 hook 触发函数
    for std_name in std_info.detected_standards:
        hijack_funcs = ERC_HIJACKABLE_CALLS.get(std_name, [])
        for func_name in hijack_funcs:
            if func_name.lower() in call_text.lower():
                if std_name == "ERC721":
                    return True, f"ERC721 {func_name}() — 触发 onERC721Received hook"
                elif std_name == "ERC777":
                    return True, f"ERC777 {func_name}() — 触发 tokensToSend/tokensReceived hook"
                elif std_name == "ERC1155":
                    return True, f"ERC1155 {func_name}() — 触发 onERC1155Received hook"
                elif std_name == "ERC1363":
                    return True, f"ERC1363 {func_name}() — 触发 onTransferReceived hook"
                else:
                    return True, f"{std_name} {func_name}() — 可能触发回调 hook"

    # 检查通用外部调用
    if ".transfer(" in call_text or ".send(" in call_text:
        return True, "transfer/send 调用 — 向外部地址发送 ETH 可触发 fallback 回调"

    return False, ""


def build_standards_summary(source: str, existing_summary: str = "") -> str:
    """构建合约标准增强摘要。

    将标准语义信息注入到现有静态分析摘要中。
    """
    std_info = detect_contract_standard(source)
    lines: list[str] = []

    # 标准检测
    if std_info.detected_standards:
        lines.append(
            f"[STANDARD] 检测到合约遵循标准: {', '.join(std_info.detected_standards)}"
        )
        for std in std_info.detected_standards:
            hijack = ERC_HIJACKABLE_CALLS.get(std, [])
            if hijack:
                lines.append(
                    f"  ⚠ {std} 可劫持函数: {', '.join(hijack)} — "
                    "这些函数执行时会触发 hook 回调，控制权转移到外部"
                )
            else:
                lines.append(f"  ℹ {std} 标准 transfer 通常不触发 hook")
    else:
        lines.append(
            "[STANDARD] 未检测到已知 ERC 标准 — 外部调用可劫持性需通过低级调用模式判断"
        )

    # 保护机制
    if std_info.has_reentrancy_guard:
        lines.append(f"[PROTECTION] ✓ 检测到重入保护: {std_info.guard_details}")
    else:
        lines.append("[PROTECTION] ✗ 未检测到 ReentrancyGuard / nonReentrant 保护")

    # 注入到原摘要
    enhanced = "\n".join(lines)
    if existing_summary:
        enhanced = enhanced + "\n\n---原始静态分析---\n" + existing_summary

    return enhanced


def classify_external_calls(source: str) -> list[dict[str, Any]]:
    """分类合约中的所有外部调用。

    对每个外部调用判断：hijackable? exploitable (direct/indirect)?
    """
    std_info = detect_contract_standard(source)
    calls: list[dict[str, Any]] = []

    # 查找所有外部调用模式
    call_patterns = [
        (r'(\.call\s*\{[^}]+\}\s*\([^)]*\))', 'low-level'),
        (r'(\.call\.value\s*\([^)]*\))', 'low-level-old'),
        (r'(\.transfer\s*\([^)]*\))', 'transfer'),
        (r'(\.send\s*\([^)]*\))', 'send'),
        (r'(\w+\.transferFrom\s*\([^)]*\))', 'ERC-transferFrom'),
        (r'(\w+\.safeTransferFrom\s*\([^)]*\))', 'ERC721-transfer'),
        (r'(\w+\.transfer\s*\([^)]*\))', 'token-transfer'),
    ]

    for pattern, call_type in call_patterns:
        for match in re.finditer(pattern, source, re.IGNORECASE):
            hijackable, reason = is_external_call_hijackable(match.group(0), std_info)
            calls.append({
                "text": match.group(0).strip(),
                "type": call_type,
                "hijackable": hijackable,
                "reason": reason,
                "line": source[:match.start()].count("\n") + 1,
            })

    return calls
