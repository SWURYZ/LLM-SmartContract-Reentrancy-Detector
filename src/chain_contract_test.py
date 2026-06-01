#!/usr/bin/env python3
"""
链上真实合约测试脚本（LLM4Re 论文要求）

使用论文中列出的 3 个以太坊主网合约地址：
  1. The DAO (0xbb9bc244d798123fde783fcc1c72d3bb8c189413)
  2. Lendf.Me (0x0eee3e3828a45f7601d5f54bf49bb01d1a9df5ea)
  3. 0xf91546835f756DA0c10cFa0CDA95b15577b84aA7 (需从 Etherscan 获取)

用法:
  python3 src/chain_contract_test.py --backend openai --model deepseek-chat
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from preprocess import PreprocessResult, preprocess_contract, write_preprocess_result
from main import build_prompt, ExperimentRunSpec, DatasetSample

CHAIN_CONTRACTS = {
    "TheDAO": {
        "file": "external/onchain_cases/TheDAO_DAO.sol",
        "address": "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
        "label": True,   # Known reentrancy victim
        "category": "standard_reentrancy",
        "fallback_address": "Lendf.Me 主合约",
    },
    "LendfMe": {
        "file": "external/onchain_cases/LendfMe_MoneyMarket.sol",
        "address": "0x0eee3e3828a45f7601d5f54bf49bb01d1a9df5ea",
        "label": True,   # Known reentrancy victim
        "category": "cross_contract_reentrancy",
        "fallback_address": "Lendf.Me 主合约",
    },
}

# 论文推荐的 profile 用于链上测试
CHAIN_TEST_PROFILES = [
    "baseline_raw",
    "crop_slither",
    "reentrancy_slice_v1",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Chain contract reentrancy test")
    parser.add_argument("--project-root", default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output-root", default=None)
    parser.add_argument("--backend", choices=["heuristic", "openai"], default="openai")
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--profiles", nargs="+", default=CHAIN_TEST_PROFILES)
    parser.add_argument("--run-id", default="chain-contract-test-20260601")
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    output_root = Path(args.output_root or (project_root / "runs" / args.run_id)).resolve()
    prompts_root = project_root / "prompts"

    if output_root.exists():
        import shutil
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True)

    from main import resolve_run_spec, ABLATION_RUNS

    # 临时注册 reentrancy_slice_v1（确保在 ABLATION_RUNS 中）
    if "reentrancy_slice_v1" not in ABLATION_RUNS:
        from main import ExperimentRunSpec as ERS
        ABLATION_RUNS["reentrancy_slice_v1"] = ERS(
            name="reentrancy_slice_v1",
            template_name="baseline_summary_prompt.txt",
            use_raw_context=False,
            include_static_summary=True,
            include_support_files=False,
            description="reentrancy slice v1",
        )

    run_specs = [resolve_run_spec(name) for name in args.profiles]

    from llm_client import OpenAICompatibleClient
    client = None
    if args.backend == "openai":
        client = OpenAICompatibleClient(model=args.model, base_url=args.base_url)

    (output_root / "run_config.json").write_text(
        json.dumps({
            "run_id": args.run_id,
            "model": args.model,
            "backend": args.backend,
            "profiles": args.profiles,
            "contracts": list(CHAIN_CONTRACTS.keys()),
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    for run_spec in run_specs:
        run_dir = output_root / run_spec.name
        run_dir.mkdir(parents=True, exist_ok=True)
        records = []

        for name, info in CHAIN_CONTRACTS.items():
            main_file = project_root / info["file"]
            if not main_file.exists():
                print(f"  SKIP {name}: file not found ({main_file})")
                continue

            print(f"  [{run_spec.name}] Testing {name} ({info['address'][:10]}...) ...")

            slice_mode = "reentrancy_slice_v1" if run_spec.name == "reentrancy_slice_v1" else "risk"
            preprocess_result = preprocess_contract(main_file, [], slice_mode=slice_mode)

            sample = DatasetSample(
                sample_id=f"chain__{name}",
                category=info["category"],
                variant="chain_contract",
                label=info["label"],
                label_source="known_exploit",
                source_name="onchain_cases",
                source_root=str(project_root / "external" / "onchain_cases"),
                main_file=str(main_file),
                support_files=[],
            )

            prompt_text = build_prompt(sample, preprocess_result, prompts_root, run_spec)

            sample_dir = run_dir / name
            sample_dir.mkdir(parents=True, exist_ok=True)
            write_preprocess_result(preprocess_result, sample_dir / "preprocess.json")
            (sample_dir / "prompt.txt").write_text(prompt_text, encoding="utf-8")

            if args.backend == "heuristic":
                from main import heuristic_predict
                prediction = heuristic_predict(sample, preprocess_result)
            else:
                prediction = client.complete(prompt_text)

            record = {
                "run_id": args.run_id,
                "profile": run_spec.name,
                "contract": name,
                "address": info["address"],
                "label": info["label"],
                "prediction": prediction.to_dict(),
                "correct": prediction.is_vulnerable == info["label"],
            }
            records.append(record)
            (sample_dir / "prediction.json").write_text(
                json.dumps(record, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print(f"    → vulnerable={prediction.is_vulnerable}, correct={record['correct']}, conf={prediction.confidence:.2f}")

        # Summary
        from main import compute_metrics
        metrics = compute_metrics(records)
        metrics["profile"] = run_spec.name
        (run_dir / "metrics.json").write_text(
            json.dumps(metrics, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"  [{run_spec.name}] Acc={metrics['accuracy']:.4f}")

    print(f"\nOutput: {output_root}")


if __name__ == "__main__":
    main()
