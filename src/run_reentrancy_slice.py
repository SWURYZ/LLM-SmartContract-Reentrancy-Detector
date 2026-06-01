#!/usr/bin/env python3
"""
数据集优化 Runner：读取全部合约 → 全局统计 → 切片 → 输出到 contracts_reentrancy_slice_v1/

用法:
  python3 src/run_reentrancy_slice.py
  python3 src/run_reentrancy_slice.py --max-chars 3800 --min-lines 5
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# 确保 src 在 path 中
sys.path.insert(0, str(Path(__file__).resolve().parent))

from reentrancy_slice_engine import (
    run_slice_pipeline,
    save_slice_results,
    GlobalStats,
    SliceResult,
)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Reentrancy slice v1 dataset optimizer")
    parser.add_argument("--project-root", default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--manifest", default=None, help="Path to manifest.json (default: contracts/manifest.json)")
    parser.add_argument("--output-dir", default=None, help="Output directory (default: contracts_reentrancy_slice_v1)")
    parser.add_argument("--max-chars", type=int, default=3800, help="Max chars per slice (default: 3800)")
    parser.add_argument("--min-lines", type=int, default=5, help="Min effective lines to keep a non-reentrancy function")
    parser.add_argument("--verbose", action="store_true", default=True)
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    manifest_path = Path(args.manifest) if args.manifest else (project_root / "contracts" / "manifest.json")
    output_dir = Path(args.output_dir) if args.output_dir else (project_root / "contracts_reentrancy_slice_v1")

    print(f"项目根目录: {project_root}")
    print(f"Manifest: {manifest_path}")
    print(f"输出目录: {output_dir}")

    # 加载 manifest
    if not manifest_path.exists():
        print(f"错误: manifest 文件不存在: {manifest_path}")
        sys.exit(1)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # 汇总每个 sample_id 对应的唯一主文件内容
    contract_files: dict[str, str] = {}
    duplicates = 0
    for item in manifest:
        sample_id = item["sample_id"]
        main_file = item["main_file"]
        source_name = item.get("source_name", "")

        # 去重：同一个 sample_id 可能来自多个数据源
        unique_key = f"{source_name}__{sample_id}"
        if unique_key in contract_files:
            duplicates += 1
            continue

        source_path = Path(main_file)
        if not source_path.exists():
            print(f"  警告: 源文件不存在: {main_file}")
            continue

        contract_files[unique_key] = source_path.read_text(encoding="utf-8")

    print(f"\n加载了 {len(contract_files)} 个唯一合约文件 (跳过 {duplicates} 个重复)")

    # 运行切片 pipeline
    print(f"\n运行切片 pipeline (max_chars={args.max_chars}, min_lines={args.min_lines}):")
    results, global_stats = run_slice_pipeline(
        contract_files,
        max_chars=args.max_chars,
        min_lines=args.min_lines,
        verbose=args.verbose,
    )

    # 保存结果
    save_slice_results(results, output_dir, global_stats)

    # 额外保存 global_stats.json 供 preprocess.py 加载
    stats_data = {
        "significant_names": sorted(global_stats.significant_names),
        "func_name_counter": global_stats.func_name_counter,
        "sorted_unique_lengths": global_stats.sorted_unique_lengths[:100],  # top 100
        "total_unique_functions": len(global_stats.sorted_unique_lengths),
        "total_functions": len(global_stats.all_func_metas),
    }
    (output_dir / "global_stats.json").write_text(
        json.dumps(stats_data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # 汇总报告
    kept = sum(1 for r in results if r.slice_text)
    filtered = sum(1 for r in results if not r.slice_text)
    total_orig = sum(r.original_len for r in results)
    total_slice = sum(r.slice_len for r in results)

    print(f"\n===== 切片完成 =====")
    print(f"总样本数: {len(results)}")
    print(f"保留: {kept}, 过滤: {filtered}")
    print(f"原始总字符: {total_orig:,}, 切片总字符: {total_slice:,}")
    print(f"平均压缩比: {total_slice / max(total_orig, 1):.2%}")
    print(f"输出目录: {output_dir}")
    print(f"显著函数数: {len(global_stats.significant_names)}")

    # 显著函数 Top 20
    if global_stats.sorted_unique_lengths:
        print(f"\n显著函数 Top 20 (全局唯一名 + 长度前10%):")
        top_n = min(20, len(global_stats.significant_names))
        top_entries = [
            (name, loc) for name, loc in global_stats.sorted_unique_lengths
            if name in global_stats.significant_names
        ][:top_n]
        for i, (name, loc) in enumerate(top_entries, 1):
            print(f"  {i:2d}. {name:<30s} LOC={loc}")


if __name__ == "__main__":
    main()
