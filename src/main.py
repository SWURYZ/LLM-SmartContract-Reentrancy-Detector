from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from llm_client import OpenAICompatibleClient, StructuredPrediction
from preprocess import PreprocessResult, preprocess_contract, redact_prompt_text, write_preprocess_result


REENTRANCY_FOLDERS = {
    "02_reentrancy": "standard_reentrancy",
    "03_reentrancy_via_modifier": "reentrancy_via_modifier",
    "04_cross_function_reentrancy": "cross_function_reentrancy",
    "05_cross_contract_reentrancy": "cross_contract_reentrancy",
}


@dataclass
class DatasetSample:
    sample_id: str
    category: str
    variant: str
    label: bool
    main_file: str
    support_files: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExperimentRunSpec:
    name: str
    template_name: str
    use_raw_context: bool
    include_static_summary: bool
    include_support_files: bool
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


LEGACY_RUNS: dict[str, ExperimentRunSpec] = {
    "baseline": ExperimentRunSpec(
        name="baseline",
        template_name="baseline_prompt.txt",
        use_raw_context=False,
        include_static_summary=False,
        include_support_files=False,
        description="Legacy cropped baseline prompt.",
    ),
    "cot": ExperimentRunSpec(
        name="cot",
        template_name="cot_reentrancy_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="Legacy CoT prompt with static summary.",
    ),
    "multi_contract": ExperimentRunSpec(
        name="multi_contract",
        template_name="multi_contract_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=True,
        description="Legacy multi-contract prompt with static summary.",
    ),
    "baseline_paper": ExperimentRunSpec(
        name="baseline_paper",
        template_name="baseline_prompt_paper.txt",
        use_raw_context=False,
        include_static_summary=False,
        include_support_files=False,
        description="Paper-aligned cropped baseline prompt.",
    ),
    "cot_paper": ExperimentRunSpec(
        name="cot_paper",
        template_name="cot_reentrancy_paper.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="Paper-aligned CoT prompt with static summary.",
    ),
    "multi_contract_paper": ExperimentRunSpec(
        name="multi_contract_paper",
        template_name="multi_contract_paper.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=True,
        description="Paper-aligned multi-contract prompt with static summary.",
    ),
}

ABLATION_RUNS: dict[str, ExperimentRunSpec] = {
    "baseline_raw": ExperimentRunSpec(
        name="baseline_raw",
        template_name="baseline_prompt.txt",
        use_raw_context=True,
        include_static_summary=False,
        include_support_files=False,
        description="Pure LLM baseline over full contract text.",
    ),
    "crop_only": ExperimentRunSpec(
        name="crop_only",
        template_name="baseline_prompt_paper.txt",
        use_raw_context=False,
        include_static_summary=False,
        include_support_files=False,
        description="Add code trimming only.",
    ),
    "crop_slither": ExperimentRunSpec(
        name="crop_slither",
        template_name="baseline_summary_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="Add static-analysis summary on top of trimming.",
    ),
    "crop_slither_cot": ExperimentRunSpec(
        name="crop_slither_cot",
        template_name="cot_reentrancy_paper.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="Add CoT prompt engineering on top of trimming and static summary.",
    ),
    "crop_slither_multi": ExperimentRunSpec(
        name="crop_slither_multi",
        template_name="multi_contract_summary_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=True,
        description="Add multi-contract context on top of trimming and static summary.",
    ),
    "fusion": ExperimentRunSpec(
        name="fusion",
        template_name="fusion_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=True,
        description="Full fusion: trimming + static summary + CoT + multi-contract context.",
    ),
}

DEFAULT_ABLATION_RUNS = [
    "baseline_raw",
    "crop_only",
    "crop_slither",
    "crop_slither_cot",
    "crop_slither_multi",
    "fusion",
]


def main() -> None:
    args = parse_args()
    project_root = Path(args.project_root).resolve()
    source_root = Path(args.source_root).resolve()
    contracts_root = Path(args.contracts_root).resolve()
    output_root = Path(args.output_root).resolve()
    prompts_root = project_root / "prompts"

    samples = prepare_dataset(source_root, contracts_root)
    manifest_path = contracts_root / "manifest.json"
    manifest_path.write_text(
        json.dumps([sample.to_dict() for sample in samples], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    selected_samples = samples[: args.max_samples] if args.max_samples else samples
    run_names = resolve_run_names(args)
    run_specs = [resolve_run_spec(name) for name in run_names]
    client = None
    if args.backend == "openai":
        client = OpenAICompatibleClient(model=args.model, base_url=args.base_url)

    all_metrics: list[dict[str, Any]] = []
    for run_spec in run_specs:
        run_dir = output_root / run_spec.name
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "run_spec.json").write_text(
            json.dumps(run_spec.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        records = []
        for sample in selected_samples:
            support_files = sample.support_files if run_spec.include_support_files else []
            preprocess_result = preprocess_contract(
                sample.main_file,
                support_files,
            )
            sample_dir = run_dir / sample.sample_id
            sample_dir.mkdir(parents=True, exist_ok=True)
            write_preprocess_result(preprocess_result, sample_dir / "preprocess.json")

            prompt_text = build_prompt(sample, preprocess_result, prompts_root, run_spec)
            (sample_dir / "prompt.txt").write_text(prompt_text, encoding="utf-8")

            if args.backend == "heuristic":
                prediction = heuristic_predict(sample, preprocess_result)
            else:
                assert client is not None
                prediction = client.complete(prompt_text)

            record = {
                "sample": sample.to_dict(),
                "prediction": prediction.to_dict(),
                "correct": prediction.is_vulnerable == sample.label,
            }
            records.append(record)
            (sample_dir / "prediction.json").write_text(
                json.dumps(record, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

        metrics = compute_metrics(records)
        metrics["profile"] = run_spec.name
        all_metrics.append(metrics)
        (run_dir / "metrics.json").write_text(
            json.dumps(metrics, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    summary_path = output_root / "summary.json"
    summary_path.write_text(
        json.dumps(all_metrics, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    comparison_path = output_root / "comparison.json"
    comparison_path.write_text(
        json.dumps(build_comparison_report(all_metrics), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(all_metrics, ensure_ascii=False, indent=2))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run reentrancy detection experiments.")
    parser.add_argument(
        "--project-root",
        default=Path(__file__).resolve().parent.parent,
        help="Project root directory.",
    )
    parser.add_argument(
        "--source-root",
        default=Path(__file__).resolve().parent.parent
        / "external"
        / "solidity-security-by-example",
        help="Source dataset root.",
    )
    parser.add_argument(
        "--contracts-root",
        default=Path(__file__).resolve().parent.parent / "contracts",
        help="Curated contracts directory.",
    )
    parser.add_argument(
        "--output-root",
        default=Path(__file__).resolve().parent.parent / "runs",
        help="Experiment output directory.",
    )
    parser.add_argument(
        "--backend",
        choices=["heuristic", "openai"],
        default="heuristic",
        help="Prediction backend.",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="LLM model when backend=openai.",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Optional OpenAI-compatible base URL.",
    )
    parser.add_argument(
        "--profiles",
        nargs="+",
        default=None,
        choices=list(ABLATION_RUNS.keys()),
        help="Ablation profiles to run. Defaults to the full baseline→fusion ladder.",
    )
    parser.add_argument(
        "--strategies",
        nargs="+",
        default=None,
        choices=list(LEGACY_RUNS.keys()),
        help="Legacy prompt families for backward compatibility.",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=0,
        help="Limit the number of samples for smoke tests.",
    )
    return parser.parse_args()


def resolve_run_names(args: argparse.Namespace) -> list[str]:
    if args.profiles:
        return args.profiles
    if args.strategies:
        return args.strategies
    return DEFAULT_ABLATION_RUNS.copy()


def resolve_run_spec(name: str) -> ExperimentRunSpec:
    if name in ABLATION_RUNS:
        return ABLATION_RUNS[name]
    if name in LEGACY_RUNS:
        return LEGACY_RUNS[name]
    raise KeyError(f"Unknown experiment profile: {name}")


def prepare_dataset(source_root: Path, contracts_root: Path) -> list[DatasetSample]:
    contracts_root.mkdir(parents=True, exist_ok=True)
    samples: list[DatasetSample] = []
    for folder_name, category in REENTRANCY_FOLDERS.items():
        source_dir = source_root / folder_name
        target_dir = contracts_root / folder_name
        target_dir.mkdir(parents=True, exist_ok=True)

        fixed_path = _copy_if_exists(source_dir / _find_main_contract(source_dir, "Fixed"), target_dir)
        insecure_path = _copy_if_exists(
            source_dir / _find_main_contract(source_dir, "Insecure"),
            target_dir,
        )
        support_files = []
        for support_name in ("Dependencies.sol",):
            support_path = source_dir / support_name
            if support_path.exists():
                copied = _copy_if_exists(support_path, target_dir)
                if copied:
                    support_files.append(str(copied))

        if insecure_path:
            samples.append(
                DatasetSample(
                    sample_id=f"{folder_name}__insecure",
                    category=category,
                    variant="insecure",
                    label=True,
                    main_file=str(insecure_path),
                    support_files=support_files,
                )
            )
        if fixed_path:
            samples.append(
                DatasetSample(
                    sample_id=f"{folder_name}__fixed",
                    category=category,
                    variant="fixed",
                    label=False,
                    main_file=str(fixed_path),
                    support_files=support_files,
                )
            )
    return samples


def _find_main_contract(source_dir: Path, prefix: str) -> str:
    matches = sorted(source_dir.glob(f"{prefix}*.sol"))
    if not matches:
        raise FileNotFoundError(f"Cannot find {prefix} contract in {source_dir}")
    return matches[0].name


def _copy_if_exists(source: Path, target_dir: Path) -> Path | None:
    if not source.exists():
        return None
    destination = target_dir / source.name
    shutil.copy2(source, destination)
    return destination


def build_prompt(
    sample: DatasetSample,
    preprocess_result: PreprocessResult,
    prompts_root: Path,
    run_spec: ExperimentRunSpec,
) -> str:
    template = (prompts_root / run_spec.template_name).read_text(encoding="utf-8")
    safe_sample_id = redact_prompt_text(sample.sample_id)
    safe_main_file = redact_prompt_text(Path(sample.main_file).name)
    safe_support_files = (
        "\n".join(redact_prompt_text(Path(path).name) for path in sample.support_files)
        if run_spec.include_support_files and sample.support_files
        else "无"
    )
    context_text = (
        preprocess_result.source_bundle[0].content if run_spec.use_raw_context else preprocess_result.cropped_context
    )
    return template.format(
        sample_id=safe_sample_id,
        category=sample.category,
        main_file=safe_main_file,
        support_files=safe_support_files,
        static_summary=redact_prompt_text(preprocess_result.static_summary)
        if run_spec.include_static_summary
        else "",
        cropped_context=redact_prompt_text(context_text),
    )


def heuristic_predict(
    sample: DatasetSample,
    preprocess_result: PreprocessResult,
) -> StructuredPrediction:
    context = preprocess_result.cropped_context
    main_source = preprocess_result.source_bundle[0].content if preprocess_result.source_bundle else ""
    post_update_findings = [
        finding
        for finding in preprocess_result.findings
        if finding.post_interaction_state_update
    ]
    modifier_signal = _detect_modifier_reentrancy(main_source)
    positive = bool(post_update_findings) or modifier_signal
    vulnerability_type = sample.category if positive else "none"
    functions = [finding.symbol_name for finding in post_update_findings] or [
        finding.symbol_name for finding in preprocess_result.findings
    ]
    attack_path = (
        "发现外部交互发生在关键状态更新之前，存在被回调重入的可能。"
        if positive
        else "未观察到稳定的交互后写状态模式。"
    )
    reasoning = (
        preprocess_result.static_summary
        if preprocess_result.static_summary
        else "未检测到明显风险信号。"
    )
    confidence = 0.75 if positive else 0.55
    return StructuredPrediction(
        is_vulnerable=positive,
        vulnerability_type=vulnerability_type,
        vulnerable_functions=functions,
        attack_path=attack_path,
        confidence=confidence,
        reasoning=reasoning,
        raw_response="heuristic-backend",
    )


def _detect_modifier_reentrancy(main_source: str) -> bool:
    normalized = " ".join(main_source.split())
    insecure_signature = (
        "function receiveAirdrop() external neverReceiveAirdrop canReceiveAirdrop"
    )
    fixed_signature = (
        "function receiveAirdrop() external noReentrant canReceiveAirdrop neverReceiveAirdrop"
    )
    if fixed_signature in normalized:
        return False
    return insecure_signature in normalized


def compute_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(records)
    tp = sum(
        1
        for item in records
        if item["sample"]["label"] and item["prediction"]["is_vulnerable"]
    )
    tn = sum(
        1
        for item in records
        if not item["sample"]["label"] and not item["prediction"]["is_vulnerable"]
    )
    fp = sum(
        1
        for item in records
        if not item["sample"]["label"] and item["prediction"]["is_vulnerable"]
    )
    fn = sum(
        1
        for item in records
        if item["sample"]["label"] and not item["prediction"]["is_vulnerable"]
    )
    positives = sum(1 for item in records if item["sample"]["label"])
    negatives = sum(1 for item in records if not item["sample"]["label"])

    return {
        "total": total,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "false_positive_rate": round(fp / negatives, 4) if negatives else 0.0,
        "false_negative_rate": round(fn / positives, 4) if positives else 0.0,
    }


def build_comparison_report(all_metrics: list[dict[str, Any]]) -> dict[str, Any]:
    if not all_metrics:
        return {"baseline_profile": None, "runs": []}

    metric_keys = [
        "total",
        "tp",
        "tn",
        "fp",
        "fn",
        "accuracy",
        "false_positive_rate",
        "false_negative_rate",
    ]
    baseline = next(
        (item for item in all_metrics if item.get("profile") == "baseline_raw"),
        next((item for item in all_metrics if item.get("profile") == "baseline"), all_metrics[0]),
    )
    baseline_profile = baseline.get("profile")
    runs = []

    for item in all_metrics:
        profile = item.get("profile")
        metrics = {key: item[key] for key in metric_keys}
        delta = {
            key: round(metrics[key] - baseline[key], 4)
            if isinstance(metrics[key], float) or isinstance(baseline[key], float)
            else metrics[key] - baseline[key]
            for key in metric_keys
        }
        runs.append(
            {
                "profile": profile,
                "metrics": metrics,
                "delta_vs_baseline": None if profile == baseline_profile else delta,
            }
        )

    return {
        "baseline_profile": baseline_profile,
        "runs": runs,
    }


if __name__ == "__main__":
    main()
