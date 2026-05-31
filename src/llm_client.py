from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class StructuredPrediction:
    is_vulnerable: bool
    vulnerability_type: str
    vulnerable_functions: list[str]
    attack_path: str
    confidence: float
    reasoning: str
    raw_response: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_vulnerable": self.is_vulnerable,
            "vulnerability_type": self.vulnerability_type,
            "vulnerable_functions": self.vulnerable_functions,
            "attack_path": self.attack_path,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "raw_response": self.raw_response,
        }


class OpenAICompatibleClient:
    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.0,
    ) -> None:
        from openai import OpenAI

        self.model = model
        self.temperature = temperature
        resolved_api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not resolved_api_key:
            raise RuntimeError(
                "未检测到 OPENAI_API_KEY。请先配置环境变量，或改用 --backend heuristic。"
            )
        self.client = OpenAI(api_key=resolved_api_key, base_url=base_url or os.getenv("OPENAI_BASE_URL"))

    def complete(self, prompt: str, system_prompt: str | None = None) -> StructuredPrediction:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            messages=messages,
        )
        content = response.choices[0].message.content or ""
        return parse_prediction(content)


def parse_prediction(response_text: str) -> StructuredPrediction:
    data = _extract_json_object(response_text)
    if data is None:
        data = _extract_labeled_fields(response_text)

    is_vulnerable = _coerce_bool(data.get("is_vulnerable"))
    vulnerability_type = str(data.get("vulnerability_type", "unknown"))
    vulnerable_functions = _coerce_functions(data.get("vulnerable_functions"))
    attack_path = str(data.get("attack_path", "")).strip()
    confidence = _coerce_confidence(data.get("confidence"))
    reasoning = str(data.get("reasoning", "")).strip()

    return StructuredPrediction(
        is_vulnerable=is_vulnerable,
        vulnerability_type=vulnerability_type,
        vulnerable_functions=vulnerable_functions,
        attack_path=attack_path,
        confidence=confidence,
        reasoning=reasoning,
        raw_response=response_text,
    )


def _extract_json_object(response_text: str) -> dict[str, Any] | None:
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


def _extract_labeled_fields(response_text: str) -> dict[str, Any]:
    mapping = {
        "is_vulnerable": r"(?:是否有漏洞|Is\s+Vulnerable)\s*[:：]\s*(.+)",
        "vulnerability_type": r"(?:漏洞类型|Vulnerability\s+Type)\s*[:：]\s*(.+)",
        "vulnerable_functions": r"(?:漏洞函数|Vulnerable\s+Functions?)\s*[:：]\s*(.+)",
        "attack_path": r"(?:攻击路径推演|Attack\s+Path)\s*[:：]\s*([\s\S]+?)(?:\n(?:置信度|Confidence|理由|Reasoning)\s*[:：]|$)",
        "confidence": r"(?:置信度|Confidence)\s*[:：]\s*(.+)",
        "reasoning": r"(?:理由|Reasoning)\s*[:：]\s*([\s\S]+)$",
    }
    result: dict[str, Any] = {}
    for key, pattern in mapping.items():
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            result[key] = match.group(1).strip()
    return result


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    return text in {"true", "yes", "y", "1", "存在", "有", "vulnerable"}


def _coerce_functions(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            loaded = json.loads(text)
            if isinstance(loaded, list):
                return [str(item).strip() for item in loaded if str(item).strip()]
        except json.JSONDecodeError:
            pass
    return [item.strip() for item in re.split(r"[,，;；\n]+", text) if item.strip()]


def _coerce_confidence(value: Any) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, min(float(value), 1.0))
    text = str(value).strip().replace("%", "")
    if not text:
        return 0.0
    try:
        number = float(text)
    except ValueError:
        return 0.0
    if number > 1:
        number = number / 100.0
    return max(0.0, min(number, 1.0))
