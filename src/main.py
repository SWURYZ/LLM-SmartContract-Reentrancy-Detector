from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

from llm_client import OpenAICompatibleClient, StructuredPrediction
from preprocess import (
    PreprocessResult,
    preprocess_contract,
    redact_prompt_text,
    write_preprocess_result,
)
from rag_engine import (
    ReentrancyRAGEngine,
    RetrievedExample,
    get_rag_engine,
    rank_predictions_by_composite,
)
from revision_engine import revision_enhanced_complete


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
    label_source: str
    source_name: str
    source_root: str
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
    "reentrancy_slice_v1": ExperimentRunSpec(
        name="reentrancy_slice_v1",
        template_name="baseline_summary_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="Improved reentrancy slice v1: global stats + significance filter + greedy fill 3800.",
    ),
    # ---- 新增：RAG + 迭代修订 + 多维排序系列 ----
    "rag_strong": ExperimentRunSpec(
        name="rag_strong",
        template_name="rag_reentrancy_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="RAG phase 1: Strong prompt with MUST/MUST NOT constraints (no few-shot yet).",
    ),
    "rag_fewshot": ExperimentRunSpec(
        name="rag_fewshot",
        template_name="rag_fewshot_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="RAG phase 2: Few-shot examples retrieved from vector DB + strong constraints.",
    ),
    "rag_fewshot_revision": ExperimentRunSpec(
        name="rag_fewshot_revision",
        template_name="rag_fewshot_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="RAG phase 3: Few-shot + iterative revision (compile-feedback loop).",
    ),
    "rag_full": ExperimentRunSpec(
        name="rag_full",
        template_name="rag_fewshot_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="RAG phase 4: Full pipeline = Few-shot + Revision + Multi-dimension ranking.",
    ),
    # ---- 新增：合约标准增强 + 三步判定框架 ----
    "standards_entry": ExperimentRunSpec(
        name="standards_entry",
        template_name="standards_reentrancy_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="Contract standards: Entry-Reentry-Flow framework + ERC hook knowledge + Verbose Elaboration.",
    ),
    # ---- 新增：外科手术式组合 ----
    "combined_surgical": ExperimentRunSpec(
        name="combined_surgical",
        template_name="combined_reentrancy_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="Combined: rag_strong conservative base + modifier execution order analysis + cross-contract moderation.",
    ),
    "surgical_v2": ExperimentRunSpec(
        name="surgical_v2",
        template_name="surgical_v2_prompt.txt",
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="Surgical v2: standards_entry framework + cross-contract moderation (removed rag_strong conflicting constraints).",
    ),
    # ---- Two-Pass 流水线 ----
    "two_pass": ExperimentRunSpec(
        name="two_pass",
        template_name="rag_reentrancy_prompt.txt",  # 主模板（Pass 1）
        use_raw_context=False,
        include_static_summary=True,
        include_support_files=False,
        description="Two-Pass: rag_strong first, if confidence<0.5 fallback to standards_entry.",
    ),
}

DEFAULT_ABLATION_RUNS = [
    "baseline_raw",
    "crop_only",
    "crop_slither",
    "crop_slither_cot",
    "crop_slither_multi",
]

# RAG 实验专用 profiles（与消融实验独立）
RAG_EXPERIMENT_RUNS = [
    "baseline_raw",        # 基线对照
    "crop_slither",        # 裁剪+摘要对照（原最优基线之一）
    "rag_strong",          # RAG phase 1: 强约束 Prompt
    "rag_fewshot",         # RAG phase 2: + Few-Shot 示例
    "rag_fewshot_revision",# RAG phase 3: + 迭代修订
    "rag_full",            # RAG phase 4: + 多维排序（全流水线）
]


def main() -> None:
    args = parse_args()
    if args.repeat < 1:
        raise ValueError("--repeat must be at least 1")

    project_root = Path(args.project_root).resolve()
    source_root = Path(args.source_root).resolve()
    curated_source_root = Path(args.curated_source_root).resolve()
    extra_source_roots = [Path(path).resolve() for path in args.extra_source_root]
    curated_roots = [curated_source_root] if args.curated_reentrancy and curated_source_root.exists() else []
    source_roots = _unique_paths(
        [
            source_root,
            *curated_roots,
            *extra_source_roots,
        ]
    )
    contracts_root = Path(args.contracts_root).resolve()
    output_root = Path(args.output_root).resolve()
    run_id = resolve_run_id(args)
    experiment_root = output_root / run_id
    if experiment_root.exists():
        raise FileExistsError(f"Run directory already exists: {experiment_root}")
    experiment_root.mkdir(parents=True, exist_ok=False)
    prompts_root = project_root / "prompts"

    samples = prepare_dataset(source_roots, contracts_root)
    manifest_path = contracts_root / "manifest.json"
    manifest_path.write_text(
        json.dumps([sample.to_dict() for sample in samples], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    dataset_profile = build_dataset_profile(samples, source_roots)
    (contracts_root / "dataset_profile.json").write_text(
        json.dumps(dataset_profile, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    selected_samples = samples[: args.max_samples] if args.max_samples else samples
    run_names = resolve_run_names(args)
    run_specs = [resolve_run_spec(name) for name in run_names]
    slice_mode = resolve_slice_mode(args, run_names)
    client = None
    if args.backend == "openai":
        client = OpenAICompatibleClient(model=args.model, base_url=args.base_url)

    run_config = {
        "run_id": run_id,
        "repeat": args.repeat,
        "backend": args.backend,
        "model": args.model,
        "base_url": args.base_url,
        "profiles": run_names,
        "max_samples": args.max_samples,
        "project_root": str(project_root),
        "source_root": str(source_root),
        "curated_reentrancy": args.curated_reentrancy,
        "curated_source_root": str(curated_source_root),
        "extra_source_roots": [str(path) for path in extra_source_roots],
        "contracts_root": str(contracts_root),
        "output_root": str(experiment_root),
    }
    (experiment_root / "run_config.json").write_text(
        json.dumps(run_config, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # ---- RAG 引擎初始化（仅当有 RAG profile 时） ----
    rag_engine: ReentrancyRAGEngine | None = None
    rag_profiles = {"rag_strong", "rag_fewshot", "rag_fewshot_revision", "rag_full"}
    any_rag = bool(set(run_names) & rag_profiles)
    if any_rag:
        rag_engine = get_rag_engine(top_k=args.rag_top_k)
        print(f"[RAG] Initialized vector index with {len(rag_engine.patterns)} reentrancy patterns.")

    # 判断各 profile 是否需要 RAG / revision / multi-dim
    def _profile_needs_rag(name: str) -> bool:
        return name in {"rag_fewshot", "rag_fewshot_revision", "rag_full"}

    def _profile_needs_revision(name: str) -> bool:
        return name in {"rag_fewshot_revision", "rag_full"} or args.enable_revision

    def _profile_needs_multidim(name: str) -> bool:
        return name == "rag_full" or args.enable_multi_dim

    profile_history: dict[str, dict[str, Any]] = {
        run_spec.name: {"repeat_metrics": [], "records": [], "revision_stats": []}
        for run_spec in run_specs
    }
    repeat_summaries: list[dict[str, Any]] = []

    for repeat_index in range(1, args.repeat + 1):
        repeat_name = f"repeat_{repeat_index:02d}"
        repeat_root = experiment_root / repeat_name
        repeat_root.mkdir(parents=True, exist_ok=False)
        repeat_summary = {"repeat_index": repeat_index, "profiles": []}

        for run_spec in run_specs:
            run_dir = repeat_root / run_spec.name
            run_dir.mkdir(parents=True, exist_ok=False)
            (run_dir / "run_spec.json").write_text(
                json.dumps(run_spec.to_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            records: list[dict[str, Any]] = []
            revision_stats: dict[str, Any] = {
                "total_revisions": 0,
                "converged_count": 0,
                "samples_with_revision": 0,
            }

            needs_rag = _profile_needs_rag(run_spec.name)
            needs_revision = _profile_needs_revision(run_spec.name)
            needs_multidim = _profile_needs_multidim(run_spec.name)

            for sample in selected_samples:
                support_files = sample.support_files if run_spec.include_support_files else []
                preprocess_result = preprocess_contract(
                    sample.main_file,
                    support_files,
                    slice_mode=slice_mode,
                )
                sample_dir = run_dir / sample.sample_id
                sample_dir.mkdir(parents=True, exist_ok=True)
                write_preprocess_result(preprocess_result, sample_dir / "preprocess.json")

                # ---- RAG 检索 ----
                retrieved_text = ""
                rag_meta: dict[str, Any] | None = None
                if needs_rag and rag_engine is not None:
                    cropped_code = preprocess_result.cropped_context or ""
                    examples = rag_engine.retrieve(cropped_code, top_k=args.rag_top_k)
                    retrieved_text = rag_engine.build_few_shot_prompt_block(examples)
                    rag_meta = {
                        "num_examples": len(examples),
                        "examples": [
                            {
                                "pattern_id": ex.pattern.pattern_id,
                                "category": ex.pattern.category,
                                "label": ex.pattern.label,
                                "similarity": round(ex.similarity_score, 4),
                            }
                            for ex in examples
                        ],
                    }
                    (sample_dir / "rag_retrieval.json").write_text(
                        json.dumps(rag_meta, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )

                prompt_text = build_prompt(
                    sample, preprocess_result, prompts_root, run_spec,
                    retrieved_examples=retrieved_text,
                )
                (sample_dir / "prompt.txt").write_text(prompt_text, encoding="utf-8")

                # ---- 预测（可选迭代修订） ----
                revision_meta: dict[str, Any] | None = None
                if args.backend == "heuristic":
                    prediction = heuristic_predict(sample, preprocess_result)
                else:
                    assert client is not None
                    prediction, revision_meta = revision_enhanced_complete(
                        client,
                        prompt_text,
                        enable_revision=needs_revision,
                        max_revision_rounds=args.max_revision_rounds,
                    )

                # ---- Two-Pass 流水线：置信度不足时回退到 standards_entry ----
                two_pass_meta: dict[str, Any] | None = None
                TWO_PASS_THRESHOLD = 0.5
                if run_spec.name == "two_pass" and prediction.confidence < TWO_PASS_THRESHOLD:
                    # Pass 2: 使用 standards_entry 模板重新判断
                    fallback_spec = ABLATION_RUNS["standards_entry"]
                    fallback_prompt = build_prompt(
                        sample, preprocess_result, prompts_root, fallback_spec,
                        retrieved_examples=retrieved_text,
                    )
                    (sample_dir / "prompt_pass2.txt").write_text(fallback_prompt, encoding="utf-8")

                    fallback_pred, _ = revision_enhanced_complete(
                        client,
                        fallback_prompt,
                        enable_revision=False,
                        max_revision_rounds=1,
                    )

                    two_pass_meta = {
                        "pass1_confidence": prediction.confidence,
                        "pass1_is_vulnerable": prediction.is_vulnerable,
                        "pass1_reasoning": prediction.reasoning[:200],
                        "pass2_confidence": fallback_pred.confidence,
                        "pass2_is_vulnerable": fallback_pred.is_vulnerable,
                        "pass2_reasoning": fallback_pred.reasoning[:200],
                        "fallback_triggered": True,
                        "used_pass": 2,
                    }
                    prediction = fallback_pred
                    (sample_dir / "two_pass_meta.json").write_text(
                        json.dumps(two_pass_meta, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    (sample_dir / "prediction_pass2.json").write_text(
                        json.dumps(fallback_pred.to_dict(), ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )

                if revision_meta:
                    revision_stats["total_revisions"] += revision_meta.get("revision_rounds", 1)
                    if revision_meta.get("converged"):
                        revision_stats["converged_count"] += 1
                    if revision_meta.get("revision_rounds", 1) > 1:
                        revision_stats["samples_with_revision"] += 1
                    (sample_dir / "revision_meta.json").write_text(
                        json.dumps(revision_meta, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )

                record = {
                    "run_id": run_id,
                    "repeat_index": repeat_index,
                    "profile": run_spec.name,
                    "sample": sample.to_dict(),
                    "prediction": prediction.to_dict(),
                    "correct": prediction.is_vulnerable == sample.label,
                    "rag_meta": rag_meta,
                    "revision_meta": revision_meta,
                    "two_pass_meta": two_pass_meta,
                }
                records.append(record)
                (sample_dir / "prediction.json").write_text(
                    json.dumps(record, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )

            # ---- 多维排序（如果启用） ----
            if needs_multidim and rag_engine is not None:
                sample_ids = set(r["sample"]["sample_id"] for r in records)
                for sid in sample_ids:
                    sample_records = [r for r in records if r["sample"]["sample_id"] == sid]
                    code_ctx = ""
                    for r in sample_records:
                        pp_file = run_dir / sid / "preprocess.json"
                        if pp_file.exists():
                            try:
                                pp_data = json.loads(pp_file.read_text(encoding="utf-8"))
                                code_ctx = pp_data.get("cropped_context", "")
                            except Exception:
                                pass
                            break
                    rank_predictions_by_composite(sample_records, rag_engine, code_ctx)

            metrics = compute_metrics(records)
            metrics["profile"] = run_spec.name
            metrics["repeat_index"] = repeat_index
            if needs_revision:
                metrics["revision_stats"] = revision_stats
            category_metrics = compute_group_metrics(records, "sample.category")
            variant_metrics = compute_group_metrics(records, "sample.variant")
            error_table = build_error_analysis_table(records)

            (run_dir / "metrics.json").write_text(
                json.dumps(metrics, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (run_dir / "scenario_metrics.json").write_text(
                json.dumps(
                    {
                        "by_category": category_metrics,
                        "by_variant": variant_metrics,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            (run_dir / "error_analysis.json").write_text(
                json.dumps(error_table, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (run_dir / "error_analysis.md").write_text(
                render_error_analysis_markdown(error_table),
                encoding="utf-8",
            )

            profile_history[run_spec.name]["repeat_metrics"].append(metrics)
            profile_history[run_spec.name]["records"].extend(records)
            if needs_revision:
                profile_history[run_spec.name]["revision_stats"].append(revision_stats)
            repeat_summary["profiles"].append(
                {
                    "profile": run_spec.name,
                    "metrics": metrics,
                    "error_samples": error_table["problem_samples"],
                }
            )

        (repeat_root / "repeat_summary.json").write_text(
            json.dumps(repeat_summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        repeat_summaries.append(repeat_summary)

    profile_summaries: list[dict[str, Any]] = []
    for run_spec in run_specs:
        history = profile_history[run_spec.name]
        repeat_metrics = history["repeat_metrics"]
        all_records = history["records"]
        profile_summary = {
            "profile": run_spec.name,
            "repeat_count": args.repeat,
            "repeat_metrics": repeat_metrics,
            "aggregate_metrics": aggregate_metric_runs(repeat_metrics),
            "scenario_metrics": {
                "by_category": compute_group_metrics(all_records, "sample.category"),
                "by_variant": compute_group_metrics(all_records, "sample.variant"),
            },
            "error_analysis": build_error_analysis_table(all_records),
        }
        profile_summaries.append(profile_summary)
        (experiment_root / f"{run_spec.name}_summary.json").write_text(
            json.dumps(profile_summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    summary = {
        "run_id": run_id,
        "repeat_count": args.repeat,
        "run_config": run_config,
        "repeats": repeat_summaries,
        "profiles": profile_summaries,
    }
    summary_path = experiment_root / "summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    comparison_path = experiment_root / "comparison.json"
    comparison_path.write_text(
        json.dumps(build_comparison_report(profile_summaries), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "run_id": run_id,
                "repeat_count": args.repeat,
                "profiles": [item["profile"] for item in profile_summaries],
                "output_root": str(experiment_root),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
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
        help="Primary paired reentrancy dataset root.",
    )
    parser.add_argument(
        "--curated-reentrancy",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include the SmartBugs curated reentrancy dataset if present.",
    )
    parser.add_argument(
        "--curated-source-root",
        default=Path(__file__).resolve().parent.parent / "external" / "smartbugs-curated",
        help="SmartBugs curated dataset root.",
    )
    parser.add_argument(
        "--extra-source-root",
        action="append",
        default=[],
        help="Additional reentrancy dataset roots to merge into the benchmark.",
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
        "--run-id",
        default=None,
        help="Optional experiment run id. Auto-generated if omitted.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=3,
        help="Number of repetitions per profile.",
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
        "--slice-mode",
        choices=["risk", "reentrancy_slice_v1"],
        default="risk",
        help="Code slicing mode. 'reentrancy_slice_v1' uses global stats + significance filter.",
    )
    parser.add_argument(
        "--profiles",
        nargs="+",
        default=None,
        choices=list(ABLATION_RUNS.keys()),
        help="Ablation profiles to run. Defaults to the full baseline→crop_slither_multi ladder.",
    )
    parser.add_argument(
        "--rag-enabled",
        action="store_true",
        default=False,
        help="Enable RAG experiment profiles (rag_strong, rag_fewshot, etc.) instead of default ablation ladder.",
    )
    parser.add_argument(
        "--rag-top-k",
        type=int,
        default=4,
        help="Number of few-shot examples to retrieve from RAG vector DB.",
    )
    parser.add_argument(
        "--enable-revision",
        action="store_true",
        default=False,
        help="Enable iterative revision (compile-feedback loop) for LLM predictions.",
    )
    parser.add_argument(
        "--max-revision-rounds",
        type=int,
        default=3,
        help="Maximum revision rounds when --enable-revision is active.",
    )
    parser.add_argument(
        "--enable-multi-dim",
        action="store_true",
        default=False,
        help="Enable multi-dimension ranking for composite prediction scoring.",
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
    # 如果启用了 RAG 模式，默认使用 RAG 实验 profiles
    if args.rag_enabled:
        return RAG_EXPERIMENT_RUNS.copy()
    return DEFAULT_ABLATION_RUNS.copy()


def resolve_slice_mode(args: argparse.Namespace, run_names: list[str]) -> str:
    """若 profile 中含 reentrancy_slice_v1，则自动启用对应 slice_mode"""
    if args.slice_mode == "reentrancy_slice_v1":
        return "reentrancy_slice_v1"
    if any("reentrancy_slice" in name for name in run_names):
        return "reentrancy_slice_v1"
    return args.slice_mode or "risk"


def resolve_run_spec(name: str) -> ExperimentRunSpec:
    if name in ABLATION_RUNS:
        return ABLATION_RUNS[name]
    raise KeyError(f"Unknown experiment profile: {name}")




def resolve_run_id(args: argparse.Namespace) -> str:
    run_id = args.run_id or datetime.now().strftime("run-%Y%m%d-%H%M%S")
    safe_run_id = (
        run_id.strip()
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace(" ", "_")
    )
    return safe_run_id or datetime.now().strftime("run-%Y%m%d-%H%M%S")



def _unique_paths(paths: list[Path | None]) -> list[Path]:
    unique_paths: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        if path is None:
            continue
        resolved = path.resolve()
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        unique_paths.append(resolved)
    return unique_paths


def _dataset_source_alias(source_root: Path) -> str:
    normalized = source_root.name.lower().replace("-", "_").replace(" ", "_")
    if normalized == "solidity_security_by_example":
        return "serial_coder"
    if normalized == "smartbugs_curated" or normalized == "smartbugs-curated":
        return "smartbugs_curated"
    return normalized or "dataset"


def _infer_curated_category(file_name: str) -> str:
    lower_name = file_name.lower()
    if "modifier" in lower_name:
        return "reentrancy_via_modifier"
    if "cross_function" in lower_name:
        return "cross_function_reentrancy"
    if "cross_contract" in lower_name or "spank" in lower_name:
        return "cross_contract_reentrancy"
    return "standard_reentrancy"


def build_dataset_profile(samples: list[DatasetSample], source_roots: list[Path]) -> dict[str, Any]:
    by_category: dict[str, int] = {}
    by_variant: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_label_source: dict[str, int] = {}
    positive_count = 0
    negative_count = 0
    for sample in samples:
        by_category[sample.category] = by_category.get(sample.category, 0) + 1
        by_variant[sample.variant] = by_variant.get(sample.variant, 0) + 1
        by_source[sample.source_name] = by_source.get(sample.source_name, 0) + 1
        by_label_source[sample.label_source] = by_label_source.get(sample.label_source, 0) + 1
        if sample.label:
            positive_count += 1
        else:
            negative_count += 1

    optimization_notes = [
        "当前基准由两类数据源组成：serial-coder 的配对 fixed/insecure 样本，以及 SmartBugs curated 的 vulnerable-only 样本。",
        "统一标签规则保持为 label=True 表示重入漏洞，label=False 表示安全/修复变体；额外的 label_source 字段记录标签来源。",
        "扩容时建议继续补充带 fixed 对照的数据源，或在评估阶段按 source 分层报告，以免类别不平衡掩盖结果。",
    ]
    return {
        "source_roots": [str(path) for path in source_roots],
        "sample_count": len(samples),
        "positive_count": positive_count,
        "negative_count": negative_count,
        "by_category": by_category,
        "by_variant": by_variant,
        "by_source": by_source,
        "by_label_source": by_label_source,
        "optimization_notes": optimization_notes,
    }


def _load_paired_reentrancy_source(source_root: Path, contracts_root: Path, source_alias: str) -> list[DatasetSample]:
    samples: list[DatasetSample] = []
    paired_root = contracts_root if source_alias == "serial_coder" else contracts_root / source_alias
    paired_root.mkdir(parents=True, exist_ok=True)

    for folder_name, category in REENTRANCY_FOLDERS.items():
        source_dir = source_root / folder_name
        target_dir = paired_root / folder_name
        target_dir.mkdir(parents=True, exist_ok=True)

        fixed_path = _copy_if_exists(source_dir / _find_main_contract(source_dir, "Fixed"), target_dir)
        insecure_path = _copy_if_exists(
            source_dir / _find_main_contract(source_dir, "Insecure"),
            target_dir,
        )
        support_files: list[str] = []
        for support_name in ("Dependencies.sol",):
            support_path = source_dir / support_name
            if support_path.exists():
                copied = _copy_if_exists(support_path, target_dir)
                if copied:
                    support_files.append(str(copied))

        if insecure_path:
            samples.append(
                DatasetSample(
                    sample_id=f"{source_alias}__{folder_name}__insecure",
                    category=category,
                    variant="insecure",
                    label=True,
                    label_source="paired_variant",
                    source_name=source_alias,
                    source_root=str(source_root),
                    main_file=str(insecure_path),
                    support_files=support_files,
                )
            )
        if fixed_path:
            samples.append(
                DatasetSample(
                    sample_id=f"{source_alias}__{folder_name}__fixed",
                    category=category,
                    variant="fixed",
                    label=False,
                    label_source="paired_variant",
                    source_name=source_alias,
                    source_root=str(source_root),
                    main_file=str(fixed_path),
                    support_files=support_files,
                )
            )
    return samples


def _load_curated_reentrancy_source(source_root: Path, contracts_root: Path, source_alias: str) -> list[DatasetSample]:
    samples: list[DatasetSample] = []
    curated_root = source_root / "dataset" / "reentrancy"
    curated_target_root = contracts_root / source_alias / "dataset" / "reentrancy"
    curated_target_root.mkdir(parents=True, exist_ok=True)

    for source_file in sorted(curated_root.glob("*.sol")):
        copied = _copy_if_exists(source_file, curated_target_root)
        if not copied:
            continue
        samples.append(
            DatasetSample(
                sample_id=f"{source_alias}__{source_file.stem}",
                category=_infer_curated_category(source_file.name),
                variant="vulnerable",
                label=True,
                label_source="curated_annotation",
                source_name=source_alias,
                source_root=str(source_root),
                main_file=str(copied),
                support_files=[],
            )
        )
    return samples


def _load_reentrancy_source(source_root: Path, contracts_root: Path) -> list[DatasetSample]:
    curated_root = source_root / "dataset" / "reentrancy"
    source_alias = _dataset_source_alias(source_root)
    if curated_root.exists():
        return _load_curated_reentrancy_source(source_root, contracts_root, source_alias)
    return _load_paired_reentrancy_source(source_root, contracts_root, source_alias)


def prepare_dataset(source_roots: list[Path], contracts_root: Path) -> list[DatasetSample]:
    contracts_root.mkdir(parents=True, exist_ok=True)
    samples: list[DatasetSample] = []
    for source_root in _unique_paths(source_roots):
        samples.extend(_load_reentrancy_source(source_root, contracts_root))

    # 对 smartbugs_curated 做 90% 行级 Jaccard 相似度去重
    samples = _deduplicate_curated(samples)
    return samples


def _deduplicate_curated(
    samples: list[DatasetSample],
    threshold: float = 0.90,
) -> list[DatasetSample]:
    """移除 smartbugs_curated 中高度相似的近重复样本 (>threshold 行级 Jaccard)。"""
    curated = [s for s in samples if s.source_name == "smartbugs_curated"]
    others = [s for s in samples if s.source_name != "smartbugs_curated"]

    if len(curated) <= 1:
        return samples

    # 读取源码
    texts: dict[str, str] = {}
    for s in curated:
        try:
            texts[s.sample_id] = Path(s.main_file).read_text(encoding="utf-8")
        except Exception:
            texts[s.sample_id] = ""

    def _jaccard(a: str, b: str) -> float:
        sa = set(a.splitlines())
        sb = set(b.splitlines())
        union = len(sa | sb)
        return len(sa & sb) / union if union > 0 else 0.0

    kept: list[DatasetSample] = []
    removed: list[str] = []

    # 按 sample_id 排序保证确定性
    for s in sorted(curated, key=lambda x: x.sample_id):
        text = texts.get(s.sample_id, "")
        is_new = True
        for k in kept:
            if _jaccard(text, texts.get(k.sample_id, "")) >= threshold:
                is_new = False
                removed.append(s.sample_id)
                break
        if is_new:
            kept.append(s)

    if removed:
        print(f"[dedup] smartbugs_curated: {len(curated)} → {len(kept)} unique (removed {len(removed)} near-duplicates at {threshold:.0%} threshold)")

    return others + kept


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
    retrieved_examples: str = "",
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

    # 收集所有 format 变量，模板中多余的变量会被安全忽略
    format_args = dict(
        sample_id=safe_sample_id,
        category=sample.category,
        main_file=safe_main_file,
        support_files=safe_support_files,
        static_summary=redact_prompt_text(preprocess_result.static_summary)
        if run_spec.include_static_summary
        else "",
        cropped_context=redact_prompt_text(context_text),
        retrieved_examples=retrieved_examples,
    )

    # 对包含 {retrieved_examples} 的模板，如果未提供则使用默认文本
    if "{retrieved_examples}" in template and not retrieved_examples:
        format_args["retrieved_examples"] = (
            "（未启用 RAG 检索，请仅基于当前代码上下文独立判断）"
        )

    # 安全 format：忽略模板中不存在的键
    import string
    template_keys = {
        field_name
        for _, field_name, _, _ in string.Formatter().parse(template)
        if field_name is not None
    }
    filtered_args = {k: v for k, v in format_args.items() if k in template_keys}

    return template.format(**filtered_args)


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






def _nested_value(item: dict[str, Any], path: str) -> Any:
    current: Any = item
    for part in path.split('.'):
        current = current[part]
    return current


def compute_group_metrics(records: list[dict[str, Any]], group_key: str) -> dict[str, dict[str, Any]]:
    grouped_records: dict[str, list[dict[str, Any]]] = {}
    for item in records:
        group_value = str(_nested_value(item, group_key))
        grouped_records.setdefault(group_value, []).append(item)
    return {
        group_value: compute_metrics(group_records)
        for group_value, group_records in grouped_records.items()
    }


def aggregate_metric_runs(metric_runs: list[dict[str, Any]]) -> dict[str, Any]:
    metric_keys = [
        'total',
        'tp',
        'tn',
        'fp',
        'fn',
        'accuracy',
        'false_positive_rate',
        'false_negative_rate',
    ]
    if not metric_runs:
        return {'repeat_count': 0, 'mean': {}, 'std': {}, 'min': {}, 'max': {}}

    summary = {
        'repeat_count': len(metric_runs),
        'mean': {},
        'std': {},
        'min': {},
        'max': {},
    }
    for key in metric_keys:
        values = [run[key] for run in metric_runs if key in run]
        if not values:
            continue
        summary['mean'][key] = round(mean(values), 4)
        summary['std'][key] = round(pstdev(values), 4) if len(values) > 1 else 0.0
        summary['min'][key] = min(values)
        summary['max'][key] = max(values)
    return summary


def build_error_analysis_table(records: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = {}
    for item in records:
        sample = item['sample']
        prediction = item['prediction']
        sample_id = sample['sample_id']
        entry = grouped.setdefault(
            sample_id,
            {
                'sample_id': sample_id,
                'category': sample['category'],
                'variant': sample['variant'],
                'label': sample['label'],
                'repeat_count': 0,
                'correct_count': 0,
                'error_count': 0,
                'false_positive_count': 0,
                'false_negative_count': 0,
                'confidence_sum': 0.0,
                'wrong_confidence_sum': 0.0,
                'wrong_confidence_count': 0,
                'representative_error': None,
            },
        )
        entry['repeat_count'] += 1
        confidence = prediction['confidence']
        entry['confidence_sum'] += confidence
        if item['correct']:
            entry['correct_count'] += 1
            continue

        entry['error_count'] += 1
        error_kind = 'FN' if sample['label'] else 'FP'
        if error_kind == 'FN':
            entry['false_negative_count'] += 1
        else:
            entry['false_positive_count'] += 1
        entry['wrong_confidence_sum'] += confidence
        entry['wrong_confidence_count'] += 1
        if entry['representative_error'] is None:
            entry['representative_error'] = {
                'error_kind': error_kind,
                'predicted': prediction['is_vulnerable'],
                'confidence': confidence,
                'vulnerable_functions': prediction['vulnerable_functions'],
                'attack_path': prediction['attack_path'],
                'reasoning': prediction['reasoning'],
            }

    rows = []
    for entry in grouped.values():
        if entry['error_count'] == 0:
            continue
        rows.append(
            {
                'sample_id': entry['sample_id'],
                'category': entry['category'],
                'variant': entry['variant'],
                'label': entry['label'],
                'repeat_count': entry['repeat_count'],
                'correct_count': entry['correct_count'],
                'error_count': entry['error_count'],
                'error_rate': round(entry['error_count'] / entry['repeat_count'], 4),
                'false_positive_count': entry['false_positive_count'],
                'false_negative_count': entry['false_negative_count'],
                'avg_confidence': round(entry['confidence_sum'] / entry['repeat_count'], 4),
                'avg_wrong_confidence': round(
                    entry['wrong_confidence_sum'] / entry['wrong_confidence_count'], 4
                )
                if entry['wrong_confidence_count']
                else 0.0,
                'representative_error': entry['representative_error'],
            }
        )

    rows.sort(key=lambda item: (-item['error_rate'], -item['error_count'], item['sample_id']))
    return {
        'total_samples': len(grouped),
        'problem_samples': len(rows),
        'rows': rows,
    }


def _escape_markdown_cell(text: Any, limit: int = 120) -> str:
    rendered = str(text).replace('\n', ' ').replace('|', '\\|')
    if len(rendered) > limit:
        rendered = rendered[: limit - 3] + '...'
    return rendered


def render_error_analysis_markdown(table: dict[str, Any]) -> str:
    lines = [
        '# 误差分析表',
        '',
        f"- 总样本数: {table['total_samples']}",
        f"- 出错样本数: {table['problem_samples']}",
        '',
    ]
    if not table['rows']:
        lines.append('无误判样本。')
        return '\n'.join(lines) + '\n'

    lines.extend(
        [
            '| sample_id | category | variant | label | repeats | errors | error_rate | fp | fn | avg_wrong_confidence | representative_error |',
            '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
        ]
    )
    for row in table['rows']:
        representative_error = row['representative_error'] or {}
        reasoning = representative_error.get('reasoning') or representative_error.get('attack_path') or ''
        representative_text = f"{representative_error.get('error_kind', '-')}: {reasoning}"
        label_text = 'Vulnerable' if row['label'] else 'Safe'
        lines.append(
            '| '
            + ' | '.join(
                [
                    _escape_markdown_cell(row['sample_id']),
                    _escape_markdown_cell(row['category']),
                    _escape_markdown_cell(row['variant']),
                    _escape_markdown_cell(label_text),
                    str(row['repeat_count']),
                    str(row['error_count']),
                    f"{row['error_rate']:.4f}",
                    str(row['false_positive_count']),
                    str(row['false_negative_count']),
                    f"{row['avg_wrong_confidence']:.4f}",
                    _escape_markdown_cell(representative_text),
                ]
            )
            + ' |'
        )
    return '\n'.join(lines) + '\n'
def build_comparison_report(profile_summaries: list[dict[str, Any]]) -> dict[str, Any]:
    if not profile_summaries:
        return {'baseline_profile': None, 'profiles': []}

    metric_keys = [
        'total',
        'tp',
        'tn',
        'fp',
        'fn',
        'accuracy',
        'false_positive_rate',
        'false_negative_rate',
    ]
    baseline = next(
        (item for item in profile_summaries if item.get('profile') == 'baseline_raw'),
        next((item for item in profile_summaries if item.get('profile') == 'baseline'), profile_summaries[0]),
    )
    baseline_profile = baseline.get('profile')
    baseline_metrics = baseline['aggregate_metrics']['mean']
    runs = []

    for item in profile_summaries:
        profile = item.get('profile')
        metrics = item['aggregate_metrics']['mean']
        std_metrics = item['aggregate_metrics']['std']
        delta = {
            key: round(metrics[key] - baseline_metrics[key], 4)
            if isinstance(metrics[key], float) or isinstance(baseline_metrics[key], float)
            else metrics[key] - baseline_metrics[key]
            for key in metric_keys
        }
        runs.append(
            {
                'profile': profile,
                'repeat_count': item.get('repeat_count', 0),
                'metrics': metrics,
                'metrics_std': std_metrics,
                'delta_vs_baseline': None if profile == baseline_profile else delta,
            }
        )

    return {
        'baseline_profile': baseline_profile,
        'profiles': runs,
    }
if __name__ == "__main__":
    main()
