"""
迭代修订模块：借鉴 PropertyGPT 的编译反馈迭代修订机制。

PropertyGPT 将编译错误作为外部 oracle 反馈给 LLM 进行迭代修订。
这里适配为：
1. JSON 格式错误 → 反馈解析错误让 LLM 修正
2. 置信度低于阈值 → 请求更详细的分析
3. is_vulnerable 与 reasoning 矛盾 → 请求自检

最大迭代次数：3 轮（与 PropertyGPT 一致）
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from llm_client import StructuredPrediction, parse_prediction


@dataclass
class RevisionResult:
    """迭代修订结果"""
    final_prediction: StructuredPrediction
    revision_rounds: int
    revision_history: list[dict[str, Any]]  # 每轮的反馈和预测
    converged: bool  # 是否收敛


def _build_revision_prompt(
    original_prompt: str,
    previous_response: str,
    revision_context: str,
    round_num: int,
    max_rounds: int,
) -> str:
    """构建修订提示词。

    借鉴 PropertyGPT Fig.5 (Common Prompt for Revising):
    - "Here is the rule I provided: {spec_res}"
    - "When this code is compiled, an error occurs: {error info}"
    - "Your task is to understand the rule, fix the code, and correct the error"
    """
    return (
        f"{original_prompt}\n\n"
        f"---\n"
        f"【第 {round_num}/{max_rounds} 轮修订请求】\n\n"
        f"你上一次的输出如下：\n"
        f"```\n{previous_response}\n```\n\n"
        f"该输出存在以下问题：\n"
        f"{revision_context}\n\n"
        f"请修正以上问题，重新输出完整的 JSON 对象。\n"
        f"只输出 JSON，不要输出额外解释。\n"
    )


def _diagnose_output(raw_response: str, prediction: StructuredPrediction) -> str | None:
    """诊断 LLM 输出中的问题，返回修订上下文或 None（无需修订）"""
    issues: list[str] = []

    # 检查 1：JSON 格式问题
    if _extract_json_object(raw_response) is None:
        issues.append(
            "- JSON 格式错误：输出不是有效的 JSON 对象。请确保输出包含 "
            "```json {{...}} ``` 代码块，或直接输出裸 JSON 对象。"
        )

    # 检查 2：confidence 在正常范围
    if prediction.confidence == 0.0:
        issues.append(
            "- confidence 为 0.0，表示不确定。请基于代码实际特征给出 0.1-1.0 之间的置信度。"
        )
    elif prediction.confidence > 1.0:
        issues.append("- confidence 超过 1.0，应为 0.0-1.0 之间的小数。")

    # 检查 3：is_vulnerable 为 True 但没有 vulnerable_functions
    if prediction.is_vulnerable and not prediction.vulnerable_functions:
        issues.append(
            "- is_vulnerable 为 true 但 vulnerable_functions 为空。"
            "如果判定有漏洞，必须列出具体的漏洞函数名。"
        )

    # 检查 4：vulnerability_type 与 is_vulnerable 一致性
    if prediction.is_vulnerable and prediction.vulnerability_type in ("none", "unknown", ""):
        issues.append(
            "- is_vulnerable 为 true 但 vulnerability_type 为 none/unknown。"
            "请指定具体的漏洞类型：standard_reentrancy / reentrancy_via_modifier "
            "/ cross_function_reentrancy / cross_contract_reentrancy"
        )
    if not prediction.is_vulnerable and prediction.vulnerability_type not in ("none", "", "unknown"):
        issues.append(
            "- is_vulnerable 为 false 但 vulnerability_type 不为 none。"
            "判定为无漏洞时，vulnerability_type 应为 \"none\"。"
        )

    # 检查 5：reasoning 太短
    if len(prediction.reasoning) < 10 and not prediction.vulnerable_functions:
        issues.append(
            "- reasoning 过于简短。请提供至少一句话的判断理由，"
            "说明为什么认为有/无漏洞。"
        )

    # 检查 6：attack_path 与 is_vulnerable 一致性
    if prediction.is_vulnerable and not prediction.attack_path:
        issues.append(
            "- is_vulnerable 为 true 但 attack_path 为空。"
            "请描述攻击者如何利用漏洞的路径。"
        )

    if not issues:
        return None

    return "当前输出存在以下问题，请修正：\n" + "\n".join(issues)


def _extract_json_object(response_text: str) -> dict[str, Any] | None:
    """与 llm_client.py 中相同的 JSON 提取逻辑"""
    fenced = re.search(r"```json\s*(\{[\s\S]*?\})\s*```", response_text, re.IGNORECASE)
    candidates = [fenced.group(1)] if fenced else []

    if not candidates:
        brace_start = response_text.find("{")
        brace_end = response_text.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            candidates.append(response_text[brace_start : brace_end + 1])

    for candidate in candidates:
        try:
            loaded = json.loads(candidate)
            if isinstance(loaded, dict):
                return loaded
        except json.JSONDecodeError:
            continue
    return None


def iterative_revise(
    client: Any,  # OpenAICompatibleClient
    original_prompt: str,
    max_rounds: int = 3,
    confidence_threshold: float = 0.3,
) -> RevisionResult:
    """迭代修订主函数。

    借鉴 PropertyGPT 的迭代修订流程：
    1. 首次调用 LLM
    2. 诊断输出问题
    3. 若有问题，构建修订 Prompt 重新调用
    4. 直到收敛或达到最大轮数

    Args:
        client: LLM 客户端
        original_prompt: 原始 Prompt
        max_rounds: 最大修订轮数（默认 3）
        confidence_threshold: 低置信度阈值

    Returns:
        RevisionResult 包含最终预测和修订历史
    """
    history: list[dict[str, Any]] = []
    current_prompt = original_prompt

    # 第一轮
    raw_response = client.client.chat.completions.create(
        model=client.model,
        temperature=client.temperature,
        messages=[{"role": "user", "content": current_prompt}],
    )
    response_text = raw_response.choices[0].message.content or ""
    prediction = parse_prediction(response_text)

    history.append({
        "round": 1,
        "prompt_snippet": current_prompt[:200],
        "raw_response": response_text,
        "prediction": prediction.to_dict(),
    })

    # 诊断
    issues = _diagnose_output(response_text, prediction)
    if issues is None and prediction.confidence >= confidence_threshold:
        return RevisionResult(
            final_prediction=prediction,
            revision_rounds=1,
            revision_history=history,
            converged=True,
        )

    # 低置信度特殊处理
    if issues is None and prediction.confidence < confidence_threshold:
        issues = (
            "置信度过低（< 0.3），说明分析不确定。请更仔细地检查代码中的：\n"
            "1. 是否有 nonReentrant / noReentrant 修饰符保护\n"
            "2. 外部调用是否在状态更新之前发生\n"
            "3. 是否可能存在回调路径\n"
            "请给出更明确、置信度更高的判断。"
        )

    # 迭代修订
    for round_num in range(2, max_rounds + 1):
        revision_prompt = _build_revision_prompt(
            original_prompt, response_text, issues, round_num, max_rounds
        )

        raw_response = client.client.chat.completions.create(
            model=client.model,
            temperature=client.temperature,
            messages=[{"role": "user", "content": revision_prompt}],
        )
        response_text = raw_response.choices[0].message.content or ""
        prediction = parse_prediction(response_text)

        history.append({
            "round": round_num,
            "previous_issues": issues,
            "raw_response": response_text,
            "prediction": prediction.to_dict(),
        })

        issues = _diagnose_output(response_text, prediction)
        if issues is None and prediction.confidence >= confidence_threshold:
            return RevisionResult(
                final_prediction=prediction,
                revision_rounds=round_num,
                revision_history=history,
                converged=True,
            )

    # 达到最大轮数，取最后一轮的预测
    return RevisionResult(
        final_prediction=prediction,
        revision_rounds=max_rounds,
        revision_history=history,
        converged=False,
    )


def revision_enhanced_complete(
    client: Any,
    prompt: str,
    enable_revision: bool = True,
    max_revision_rounds: int = 3,
) -> tuple[StructuredPrediction, dict[str, Any] | None]:
    """增强版 complete：可选迭代修订。

    Returns:
        (prediction, revision_meta): 预测结果和修订元数据
    """
    if not enable_revision:
        return client.complete(prompt), None

    result = iterative_revise(client, prompt, max_rounds=max_revision_rounds)
    meta = {
        "revision_rounds": result.revision_rounds,
        "converged": result.converged,
        "history": [
            {
                "round": h["round"],
                "confidence": h["prediction"]["confidence"],
                "is_vulnerable": h["prediction"]["is_vulnerable"],
                "vulnerability_type": h["prediction"]["vulnerability_type"],
            }
            for h in result.revision_history
        ],
    }
    return result.final_prediction, meta
