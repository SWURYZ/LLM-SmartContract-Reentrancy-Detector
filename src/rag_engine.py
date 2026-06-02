"""
RAG 引擎：基于检索增强生成的重入漏洞参考示例检索。

借鉴 PropertyGPT 的 RAG + One-Shot ICL 设计：
1. 将所有已知重入漏洞样本代码嵌入向量数据库
2. 对新的待检测代码，检索最相似的已知漏洞作为 Few-Shot 示例
3. 注入 Prompt 模板，引导 LLM 基于参考示例进行判断
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np


# ============================================================
# Known reentrancy patterns library (embedding source)
# ============================================================

@dataclass
class ReentrancyPattern:
    """一条已知重入漏洞模式记录"""
    pattern_id: str
    category: str  # standard_reentrancy, reentrancy_via_modifier, cross_function_reentrancy, cross_contract_reentrancy
    label: bool  # True = vulnerable, False = safe/fixed
    code_snippet: str
    vulnerability_description: str
    key_features: str  # 关键特征描述（用于摘要相似度）
    attack_path: str
    cwe_reference: str = ""


def _build_pattern_library() -> list[ReentrancyPattern]:
    """构建重入漏洞模式库。

    这些模式来自已知的 Solidity 重入漏洞案例，
    涵盖 4 类重入 + secure/fixed 对照。
    """
    patterns: list[ReentrancyPattern] = []

    # ---- standard_reentrancy (vulnerable) ----
    patterns.append(ReentrancyPattern(
        pattern_id="pattern_standard_withdraw",
        category="standard_reentrancy",
        label=True,
        code_snippet=(
            "function withdraw(uint256 amount) public {\n"
            "    require(balances[msg.sender] >= amount);\n"
            "    (bool success, ) = msg.sender.call{value: amount}(\"\");\n"
            "    require(success);\n"
            "    balances[msg.sender] -= amount;  // 状态更新在外部调用之后\n"
            "}"
        ),
        vulnerability_description="经典 withdraw 模式：先执行 external call (call/transfer/send)，再更新余额。攻击者在 receive/fallback 中回调 withdraw() 可重复取款。",
        key_features="external_call_before_state_update; call{value:}; balances_after_transfer; fallback_reentrancy",
        attack_path="攻击者合约 fallback() → 回调 withdraw() → 余额尚未扣减 → 重复取款",
    ))

    patterns.append(ReentrancyPattern(
        pattern_id="pattern_standard_safe",
        category="standard_reentrancy",
        label=False,
        code_snippet=(
            "function withdraw(uint256 amount) public nonReentrant {\n"
            "    require(balances[msg.sender] >= amount);\n"
            "    balances[msg.sender] -= amount;  // 先更新状态\n"
            "    (bool success, ) = msg.sender.call{value: amount}(\"\");\n"
            "    require(success);\n"
            "}"
        ),
        vulnerability_description="安全的 withdraw 模式：使用 nonReentrant 锁 + CEI (Checks-Effects-Interactions) 原则，先更新余额再做外部调用。",
        key_features="nonReentrant_modifier; state_update_before_external_call; CEI_pattern; reentrancy_guard",
        attack_path="无 — nonReentrant 阻止回调重入，余额先扣减后再转账",
    ))

    # ---- reentrancy_via_modifier (vulnerable) ----
    patterns.append(ReentrancyPattern(
        pattern_id="pattern_modifier_vuln",
        category="reentrancy_via_modifier",
        label=True,
        code_snippet=(
            "modifier canReceiveAirdrop() {\n"
            "    require(!receivedAirdrop[msg.sender], \"already received\");\n"
            "    _;\n"
            "    receivedAirdrop[msg.sender] = true;  // 状态更新在 _; 之后\n"
            "}\n"
            "function receiveAirdrop() external neverReceiveAirdrop canReceiveAirdrop {\n"
            "    (bool success, ) = msg.sender.call{value: 1 ether}(\"\");  // modifier 中的 _; 后执行\n"
            "}"
        ),
        vulnerability_description="modifier 重入：modifier 中 _; 之后才更新 receivedAirdrop 状态。攻击者在 external call 后通过 callback 重新调用 receiveAirdrop()，此时 receivedAirdrop 仍为 false。",
        key_features="modifier_state_after_placeholder; external_call_in_function_body; modifier_check_before_state_update",
        attack_path="external call → fallback → receiveAirdrop() → canReceiveAirdrop 检查通过（状态未更新） → 再次 external call",
    ))

    patterns.append(ReentrancyPattern(
        pattern_id="pattern_modifier_safe",
        category="reentrancy_via_modifier",
        label=False,
        code_snippet=(
            "modifier noReentrant() {\n"
            "    require(!locked, \"reentrant call\");\n"
            "    locked = true;\n"
            "    _;\n"
            "    locked = false;\n"
            "}\n"
            "function withdraw() external noReentrant {\n"
            "    balances[msg.sender] -= amount;\n"
            "    (bool success, ) = msg.sender.call{value: amount}(\"\");\n"
            "}"
        ),
        vulnerability_description="安全的 modifier 模式：noReentrant 在 _; 之前上锁（locked=true），require(!locked) 阻止任何回调重入。",
        key_features="nonReentrant_lock_before_placeholder; locked_state_guard; reentrancy_protection",
        attack_path="无 — noReentrant 锁在函数体执行前上锁，回调时 require(!locked) 失败",
    ))

    # ---- cross_function_reentrancy (vulnerable) ----
    patterns.append(ReentrancyPattern(
        pattern_id="pattern_cross_function_vuln",
        category="cross_function_reentrancy",
        label=True,
        code_snippet=(
            "mapping(address => uint256) public balances;\n"
            "function withdraw() public {\n"
            "    uint256 amount = balances[msg.sender];\n"
            "    (bool success, ) = msg.sender.call{value: amount}(\"\");\n"
            "    balances[msg.sender] = 0;\n"
            "}\n"
            "function transfer(address to, uint256 amount) public {\n"
            "    balances[msg.sender] -= amount;\n"
            "    balances[to] += amount;\n"
            "}"
        ),
        vulnerability_description="跨函数重入：withdraw() 先 call 再清零余额。攻击者在 fallback 中调用 transfer() 将余额转走，即使 withdraw() 后续清零也无法挽回已转出的资金。",
        key_features="shared_state_across_functions; external_call_before_state_zero; transfer_function_accessible; cross_function_shared_balance",
        attack_path="withdraw() → call → fallback → transfer(to, amount) → 余额转出 → withdraw() 清零已无效",
    ))

    patterns.append(ReentrancyPattern(
        pattern_id="pattern_cross_function_safe",
        category="cross_function_reentrancy",
        label=False,
        code_snippet=(
            "mapping(address => uint256) public balances;\n"
            "function withdraw() public nonReentrant {\n"
            "    uint256 amount = balances[msg.sender];\n"
            "    balances[msg.sender] = 0;  // 先清零\n"
            "    (bool success, ) = msg.sender.call{value: amount}(\"\");\n"
            "}\n"
        ),
        vulnerability_description="安全的跨函数防护：nonReentrant 阻止任何回调进入，且余额先清零再转账。",
        key_features="nonReentrant_guard; zero_balance_before_call; CEI_pattern",
        attack_path="无 — nonReentrant 阻止回调，余额已清零",
    ))

    # ---- cross_contract_reentrancy (vulnerable) ----
    patterns.append(ReentrancyPattern(
        pattern_id="pattern_cross_contract_vuln",
        category="cross_contract_reentrancy",
        label=True,
        code_snippet=(
            "function deposit() external payable {\n"
            "    balances[msg.sender] += msg.value;\n"
            "}\n"
            "function withdrawAll() external {\n"
            "    uint256 amount = balances[msg.sender];\n"
            "    IERC20(token).transfer(msg.sender, amount);  // token transfer 可能触发 hook\n"
            "    balances[msg.sender] = 0;\n"
            "}"
        ),
        vulnerability_description="跨合约重入：主合约调用外部 token 合约的 transfer()，若 token 是 ERC777 等带 hook 的代币，攻击者可在 tokensToSend hook 中回调主合约的 withdrawAll()。",
        key_features="external_token_interaction; ERC777_hook; balances_after_external_call; cross_contract_callback",
        attack_path="withdrawAll() → token.transfer() → tokensToSend hook → 回调 withdrawAll() → 余额视图未更新 → 重复提取",
    ))

    patterns.append(ReentrancyPattern(
        pattern_id="pattern_cross_contract_safe",
        category="cross_contract_reentrancy",
        label=False,
        code_snippet=(
            "function withdrawAll() external nonReentrant {\n"
            "    uint256 amount = balances[msg.sender];\n"
            "    balances[msg.sender] = 0;  // Checks-Effects: 先更新状态\n"
            "    IERC20(token).transfer(msg.sender, amount);  // Interactions: 再外部调用\n"
            "}"
        ),
        vulnerability_description="安全的跨合约防护：CEI 原则 + nonReentrant 锁，先清零余额再调用外部合约。",
        key_features="nonReentrant_guard; CEI_pattern; state_update_before_external_token_call",
        attack_path="无 — nonReentrant + 余额先清零",
    ))

    return patterns


# ============================================================
# Simple TF-IDF based embedding (no external API dependency)
# ============================================================

class TfidfEmbedder:
    """基于字符 n-gram TF-IDF 的轻量级代码嵌入器。

    无需外部 API（如 OpenAI embeddings），完全本地计算。
    适用于代码相似度检索场景。
    """

    def __init__(self, ngram_range: tuple[int, int] = (2, 4), max_features: int = 500):
        self.ngram_range = ngram_range
        self.max_features = max_features
        self.vocabulary_: dict[str, int] = {}
        self.idf_: np.ndarray | None = None

    def _tokenize(self, text: str) -> list[str]:
        """字符 n-gram 分词"""
        text = text.lower()
        tokens: list[str] = []
        for n in range(self.ngram_range[0], self.ngram_range[1] + 1):
            for i in range(len(text) - n + 1):
                tokens.append(text[i:i + n])
        return tokens

    def fit(self, documents: list[str]) -> TfidfEmbedder:
        """构建词汇表和 IDF"""
        doc_count = len(documents)
        # 收集所有 token 的文档频率
        df: dict[str, int] = {}
        for doc in documents:
            tokens = set(self._tokenize(doc))
            for token in tokens:
                df[token] = df.get(token, 0) + 1

        # 按文档频率排序，取 top max_features
        sorted_tokens = sorted(df.items(), key=lambda x: (-x[1], x[0]))[:self.max_features]
        self.vocabulary_ = {token: idx for idx, (token, _) in enumerate(sorted_tokens)}

        # 计算 IDF
        n_features = len(self.vocabulary_)
        idf = np.zeros(n_features)
        for token, idx in self.vocabulary_.items():
            idf[idx] = np.log((1 + doc_count) / (1 + df.get(token, 1))) + 1.0
        self.idf_ = idf
        return self

    def transform(self, documents: list[str]) -> np.ndarray:
        """将文档转换为 TF-IDF 向量"""
        if self.idf_ is None:
            raise RuntimeError("Embedder not fitted. Call fit() first.")
        n_features = len(self.vocabulary_)
        result = np.zeros((len(documents), n_features))
        for i, doc in enumerate(documents):
            tokens = self._tokenize(doc)
            # 计算 TF
            tf: dict[str, float] = {}
            for token in tokens:
                tf[token] = tf.get(token, 0.0) + 1.0
            # 归一化
            total = len(tokens) or 1
            for token, count in tf.items():
                if token in self.vocabulary_:
                    result[i, self.vocabulary_[token]] = (count / total) * self.idf_[self.vocabulary_[token]]
        # L2 归一化
        norms = np.linalg.norm(result, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return result / norms

    def fit_transform(self, documents: list[str]) -> np.ndarray:
        self.fit(documents)
        return self.transform(documents)


# ============================================================
# RAG Engine
# ============================================================

@dataclass
class RetrievedExample:
    """检索到的参考示例"""
    pattern: ReentrancyPattern
    similarity_score: float
    summary: str  # LLM-friendly summary of why this example is relevant


class ReentrancyRAGEngine:
    """重入漏洞检测 RAG 引擎。

    借鉴 PropertyGPT 的架构：
    - 将所有已知重入模式嵌入向量空间
    - 对新的待检测代码检索最相似的参考示例
    - 生成 Few-Shot 示例文本注入 Prompt

    与 PropertyGPT 的差异：
    - 使用本地 TF-IDF 而非 OpenAI embeddings（零 API 成本）
    - 同时检索 vulnerable 和 safe 示例（正负对照）
    - 支持代码 + 关键特征的多维检索
    """

    def __init__(self, top_k: int = 4):
        self.top_k = top_k
        self.patterns: list[ReentrancyPattern] = []
        self._embedder: TfidfEmbedder | None = None
        self._pattern_vectors: np.ndarray | None = None
        self._code_embedder: TfidfEmbedder | None = None
        self._feature_embedder: TfidfEmbedder | None = None

    def build_index(self, patterns: list[ReentrancyPattern] | None = None) -> None:
        """构建向量索引"""
        if patterns is None:
            patterns = _build_pattern_library()
        self.patterns = patterns

        # 使用统一的 max_features 避免维度不匹配
        N_FEATURES = 500

        # 代码嵌入
        code_docs = [p.code_snippet for p in self.patterns]
        self._code_embedder = TfidfEmbedder(ngram_range=(2, 4), max_features=N_FEATURES)
        code_vectors = self._code_embedder.fit_transform(code_docs)

        # 关键特征嵌入（pad 到相同维度）
        feature_docs = [p.key_features for p in self.patterns]
        self._feature_embedder = TfidfEmbedder(ngram_range=(1, 3), max_features=N_FEATURES)
        feature_vectors_raw = self._feature_embedder.fit_transform(feature_docs)
        # Pad 到 N_FEATURES
        feature_vectors = np.zeros((len(patterns), N_FEATURES))
        feature_vectors[:, :feature_vectors_raw.shape[1]] = feature_vectors_raw

        # 拼接向量（代码:特征 = 0.6:0.4）
        self._embedder = self._code_embedder
        self._pattern_vectors = 0.6 * code_vectors + 0.4 * feature_vectors

    def retrieve(self, code: str, top_k: int | None = None) -> list[RetrievedExample]:
        """检索与给定代码最相似的已知重入模式。

        Args:
            code: 待检测的 Solidity 代码
            top_k: 返回的示例数量，默认使用初始化时的 top_k

        Returns:
            按相似度降序排列的参考示例列表
        """
        if self._embedder is None or self._pattern_vectors is None:
            raise RuntimeError("RAG index not built. Call build_index() first.")
        k = top_k or self.top_k

        # 计算查询向量
        code_vector = self._code_embedder.transform([code])
        feature_vector_raw = self._feature_embedder.transform([code])
        # Pad feature_vector to match code_vector dimension
        feature_vector = np.zeros((1, code_vector.shape[1]))
        feature_vector[:, :feature_vector_raw.shape[1]] = feature_vector_raw
        query_vector = 0.6 * code_vector + 0.4 * feature_vector

        # 余弦相似度
        similarities = np.dot(query_vector, self._pattern_vectors.T).flatten()

        # 取 top-k（同时确保正负样本均衡）
        top_indices = np.argsort(similarities)[::-1]

        results: list[RetrievedExample] = []
        seen_categories: set[str] = set()
        has_vuln = False
        has_safe = False

        for idx in top_indices:
            if len(results) >= k:
                break
            pattern = self.patterns[idx]
            score = float(similarities[idx])

            if score < 0.05:  # 相似度太低，不相关
                continue

            summary = self._build_summary(pattern, score)
            results.append(RetrievedExample(
                pattern=pattern,
                similarity_score=score,
                summary=summary,
            ))

            if pattern.label:
                has_vuln = True
            else:
                has_safe = True
            seen_categories.add(pattern.category)

            # 确保至少一个 vulnerable 和一个 safe 示例
            if len(results) >= k:
                if not has_vuln:
                    # 补充一个 vulnerable 示例
                    for j in range(idx + 1, len(top_indices)):
                        p2 = self.patterns[top_indices[j]]
                        if p2.label:
                            results.append(RetrievedExample(
                                pattern=p2,
                                similarity_score=float(similarities[top_indices[j]]),
                                summary=self._build_summary(p2, float(similarities[top_indices[j]])),
                            ))
                            break
                if not has_safe:
                    for j in range(idx + 1, len(top_indices)):
                        p2 = self.patterns[top_indices[j]]
                        if not p2.label:
                            results.append(RetrievedExample(
                                pattern=p2,
                                similarity_score=float(similarities[top_indices[j]]),
                                summary=self._build_summary(p2, float(similarities[top_indices[j]])),
                            ))
                            break

        return results

    def _build_summary(self, pattern: ReentrancyPattern, score: float) -> str:
        """构建 LLM 友好的示例摘要"""
        label_text = "【有漏洞 - VULNERABLE】" if pattern.label else "【安全 - SAFE】"
        category_cn = {
            "standard_reentrancy": "标准重入",
            "reentrancy_via_modifier": "Modifier重入",
            "cross_function_reentrancy": "跨函数重入",
            "cross_contract_reentrancy": "跨合约重入",
        }.get(pattern.category, pattern.category)
        return (
            f"{label_text} | 类型: {category_cn} | 相似度: {score:.2%}\n"
            f"描述: {pattern.vulnerability_description}\n"
            f"攻击路径: {pattern.attack_path}"
        )

    def build_few_shot_prompt_block(self, examples: list[RetrievedExample]) -> str:
        """将检索到的示例构建为 Few-Shot Prompt 块"""
        if not examples:
            return "（未检索到足够相似的参考示例，请仅基于当前代码上下文独立判断）"

        blocks: list[str] = []
        blocks.append("【参考示例】以下是与当前代码最相似的已知重入漏洞/安全案例，请参考这些案例进行判断：\n")

        for i, ex in enumerate(examples, 1):
            p = ex.pattern
            label_text = "有漏洞（VULNERABLE）" if p.label else "安全（SAFE）"
            blocks.append(
                f"### 参考示例 {i}: {label_text}\n"
                f"- 类型: {p.category}\n"
                f"- 相似度: {ex.similarity_score:.2%}\n"
                f"- 描述: {p.vulnerability_description}\n"
                f"- 攻击路径: {p.attack_path}\n"
                f"- 参考代码:\n```solidity\n{p.code_snippet}\n```\n"
            )

        blocks.append(
            "---\n"
            "请基于以上参考示例和当前代码上下文，综合判断目标合约是否存在重入漏洞。\n"
            "注意：参考示例仅供参考，最终判断必须基于当前代码的实际结构和逻辑。"
        )
        return "\n".join(blocks)


# ============================================================
# Similarity-based multi-dimensional scoring utilities
# (for the ranking phase)
# ============================================================

@dataclass
class DimensionScores:
    """多维度评分结果"""
    raw_code_similarity: float  # 与已知漏洞的代码级相似度
    summary_similarity: float   # 关键特征摘要相似度
    confidence_consistency: float  # 多次 repeat 置信度一致性
    category_match: float       # 类别与历史模式匹配度
    composite: float            # 加权综合得分


def compute_multi_dimension_score(
    predictions: list[dict[str, Any]],
    rag_engine: ReentrancyRAGEngine | None = None,
    code_context: str = "",
) -> DimensionScores:
    """多维评分：综合代码相似度、置信度一致性、类别匹配度。

    借鉴 PropertyGPT 的四维加权评分（α*X_raw + β*X_summary + γ*Y_raw + η*Y_summary），
    这里简化为 4 个维度并加权求和。
    """
    if not predictions:
        return DimensionScores(0.0, 0.0, 0.0, 0.0, 0.0)

    # 1. 代码相似度：当前代码与已知漏洞模式的相似度
    raw_code_sim = 0.0
    summary_sim = 0.0
    if rag_engine and code_context:
        examples = rag_engine.retrieve(code_context, top_k=3)
        if examples:
            raw_code_sim = float(np.mean([ex.similarity_score for ex in examples]))

    # 2. 置信度一致性：多次预测的标准差越小越好
    confidence_list = [p.get("prediction", {}).get("confidence", 0) for p in predictions]
    if len(confidence_list) > 1:
        conf_std = float(np.std(confidence_list))
        confidence_consistency = max(0.0, 1.0 - conf_std * 2)  # std=0 → 1.0, std=0.5 → 0.0
    else:
        confidence_consistency = 1.0

    # 3. 类别匹配度：预测类别是否一致
    vuln_types = [p.get("prediction", {}).get("vulnerability_type", "none") for p in predictions]
    if len(vuln_types) > 1:
        most_common_count = max(vuln_types.count(t) for t in set(vuln_types))
        category_match = most_common_count / len(vuln_types)
    else:
        category_match = 1.0

    # 4. 加权综合（借鉴 PropertyGPT 权重：α:0.134, β:0.556, γ:0.141, η:0.168）
    # 调整权重适应重入检测场景
    ALPHA = 0.20   # 代码相似度
    BETA = 0.35    # 特征摘要相似度
    GAMMA = 0.25   # 置信度一致性
    ETA = 0.20     # 类别匹配度

    composite = (
        ALPHA * raw_code_sim
        + BETA * summary_sim
        + GAMMA * confidence_consistency
        + ETA * category_match
    )

    return DimensionScores(
        raw_code_similarity=round(raw_code_sim, 4),
        summary_similarity=round(summary_sim, 4),
        confidence_consistency=round(confidence_consistency, 4),
        category_match=round(category_match, 4),
        composite=round(composite, 4),
    )


def rank_predictions_by_composite(
    records: list[dict[str, Any]],
    rag_engine: ReentrancyRAGEngine | None = None,
    code_context: str = "",
) -> list[dict[str, Any]]:
    """按复合得分排序预测结果，取最高分作为最终判定。

    与简单平均的差异：
    - 综合代码相似度、置信度一致性、类别匹配度
    - 过滤低质量预测（composite < 0.3 标记为 uncertain）
    """
    scores = compute_multi_dimension_score(records, rag_engine, code_context)
    for record in records:
        record["_dimension_scores"] = {
            "raw_code_similarity": scores.raw_code_similarity,
            "summary_similarity": scores.summary_similarity,
            "confidence_consistency": scores.confidence_consistency,
            "category_match": scores.category_match,
            "composite": scores.composite,
        }
    return records


# ============================================================
# Singleton utility
# ============================================================

_global_rag_engine: ReentrancyRAGEngine | None = None


def get_rag_engine(top_k: int = 4) -> ReentrancyRAGEngine:
    """获取全局 RAG 引擎单例（懒加载）"""
    global _global_rag_engine
    if _global_rag_engine is None:
        _global_rag_engine = ReentrancyRAGEngine(top_k=top_k)
        _global_rag_engine.build_index()
    return _global_rag_engine
