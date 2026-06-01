# LLM-Based Smart Contract Reentrancy Detection

> **An Ablation-Driven Pipeline with DeepSeek-chat**
>
> *Iterative optimization through ablation experiments, code slicing, and prompt engineering*

---

## Abstract

Reentrancy remains one of the most critical vulnerabilities in smart contracts, yet traditional static analysis tools struggle with cross-function, cross-contract, and modifier-hidden attack patterns. This work presents a reproducible, ablation-driven pipeline that leverages Large Language Models (LLMs) for Solidity reentrancy detection. We systematically evaluate five prompt profiles on a curated 41-sample benchmark spanning four reentrancy categories. Through three rounds of iterative optimization—ablation study, reentrancy slice engine with guard injection, and prompt-level rule injection—we reduce the False Positive Rate (FPR) from 0.458 to **0.250** (a 45% reduction) while maintaining an Accuracy of 0.870. A key insight emerges: for LLMs, **system-level prompt rules significantly outperform inline code annotations**, revealing a fundamental distinction between *instruction channel* and *content channel* in LLM prompt engineering for security applications.

---

## 1. Introduction

### 1.1 Background and Motivation

Reentrancy attacks are among the most classic and devastating vulnerabilities in Ethereum smart contracts. The core risk lies in *regaining control after an external call*: when a contract performs an external interaction before completing its state updates, an attacker can re-enter the same logic through a callback, leading to repeated fund withdrawals, corrupted permission states, and bypassed access controls.

Traditional static analysis tools (e.g., Slither) are effective at identifying explicit patterns—such as `call{value:...}` followed by balance updates. However, they often miss attack paths that span **multiple functions**, **multiple contracts**, or are **hidden within modifiers**. These tools require substantial manual effort to reconstruct the full contextual picture.

Recent advances in Large Language Models (LLMs) offer a promising alternative. LLMs can process longer code contexts, integrate multi-file dependencies, and reason about *call chains* and *state mutation ordering* in natural language. However, LLM-based approaches face their own challenges: context-window noise, prompt design sensitivity, and hallucination risks.

### 1.2 Research Gap and Objectives

The central research gap we address is: **How can LLMs be effectively deployed for reentrancy detection in scenarios involving long code contexts, multi-file dependencies, and nuanced reentrancy semantics, while maintaining reproducibility and interpretability?**

Our specific objectives are:

1. Build a **fully reproducible detection pipeline** where every intermediate artifact (preprocessing results, assembled prompts, structured predictions) is persisted for auditability.
2. Employ **DeepSeek-chat** as the LLM backbone, comparing raw code input against systematically cropped, statically analyzed, and prompt-engineered variants.
3. Use **structured JSON output** to capture `is_vulnerable`, `vulnerability_type`, `vulnerable_functions`, `attack_path`, `confidence`, and `reasoning` for each prediction.
4. Conduct **ablation experiments** to quantitatively answer: *Which context modalities genuinely help, and which introduce noise?*

### 1.3 Innovations

- **Ablation-driven iterative methodology**: Each experimental round exposes a problem → targeted optimization → re-validation → closed loop.
- **Reentrancy Slice Engine v1**: A 4-rule global-statistics-based code slicing pipeline with automatic ReentrancyGuard injection.
- **Instruction-channel vs. content-channel discovery**: First empirical validation in a reentrancy detection context that LLM system prompts carry higher decision weight than inline code comments.

---

## 2. Related Work

### 2.1 Traditional Reentrancy Detection

Conventional approaches rely on manual auditing, pattern-matching rules, and static analysis frameworks. Slither [Feist et al., 2019] and similar tools can rapidly identify suspicious external call sites. However, these methods are tuned for *explicit patterns* and require auditors to manually fill in context for cross-function, cross-contract, and modifier-based reentrancy.

### 2.2 LLM-Based Vulnerability Detection

Recent studies have explored feeding full smart contract source code directly to LLMs for vulnerability classification. While LLMs can read lengthy code and perform semantic summarization, purely end-to-end approaches suffer from context-window noise, suboptimal prompt design, and hallucination. The research community has yet to establish a systematic framework for determining **which types of contextual information** (trimmed code, static analysis summaries, dependency files, reasoning chains) actually contribute to detection accuracy.

### 2.3 Our Approach

We combine static analysis, code trimming, and prompt engineering into a **reproducible experimental pipeline**. By conducting ablative experiments, we isolate the marginal contribution of each enhancement module, transforming the research question from "can LLMs find reentrancy?" to "**which preprocessing modules enable LLMs to find reentrancy most effectively?**"

---

## 3. Methodology

### 3.1 Overall Pipeline Architecture

Our detection system follows a four-stage pipeline:

```
Stage 1: Preprocessing
  Solidity source + dependencies
    → Slither static analysis (fallback: heuristic regex)
    → Code cropping (risk-focused or reentrancy_slice_v1)
    → Prompt anonymization (remove Insecure/Fixed naming bias)

Stage 2: Prompt Assembly
  Preprocessed context + static findings
    → Template-based prompt filling ({code_context}, {static_summary}, ...)
    → Structured output format specification

Stage 3: LLM Inference
  Assembled prompt
    → DeepSeek-chat (T=0, OpenAI-compatible API)
    → 300s timeout with 1 retry

Stage 4: Evaluation
  Structured JSON prediction
    → Parse is_vulnerable, vulnerability_type, vulnerable_functions, ...
    → Compute Accuracy, FPR, FNR (mean ± std, repeat=3)
    → Per-category and per-variant breakdown
```

**Design Philosophy**: Rather than treating the LLM as a black-box oracle, we decompose the detection into independently verifiable modules. All intermediate artifacts (`preprocess.json`, `prompt.txt`, `prediction.json`) are persisted, ensuring full reproducibility and auditability.

### 3.2 Code Preprocessing

The preprocessing stage (`src/preprocess.py`) performs two-channel analysis:

1. **Slither Channel** (preferred): Invokes Slither to extract `can_send_eth` functions, external call sites, and state variable reads/writes.
2. **Heuristic Channel** (fallback): Regex-based contract parsing that identifies risk-related functions, modifiers, and call patterns when Slither is unavailable.

**Code Cropping** reduces prompt noise by retaining only:
- Functions containing external calls (`call`, `delegatecall`, `transfer`, `send`)
- State variable definitions relevant to balances and locks
- Referenced modifiers and dependency interfaces

All sample identifiers and filenames are **anonymized** to prevent label leakage (e.g., "Insecure" / "Fixed" naming patterns).

### 3.3 Prompt Design and Ablation Profiles

We designed five ablation profiles, each adding one layer of complexity to isolate marginal contributions:

| Profile | Input Features | Hypothesis Tested |
|---|---|---|
| `baseline_raw` | Full contract source text | Pure LLM capability (no preprocessing) |
| `crop_only` | Cropped risk-relevant code | Does code trimming alone improve detection? |
| `crop_slither` | Cropped code + Slither summary | Does static analysis context enhance judgment? |
| `crop_slither_cot` | + Chain-of-Thought reasoning steps | Does step-by-step reasoning help? |
| `crop_slither_multi` | + Multi-contract dependency files | Do auxiliary files provide necessary context? |

**Ablation Logic**: Profiles are stacked from simple to complex. If a layer causes degradation, the added information is likely noise rather than signal. All profiles share identical sample sets, temperature (T=0), and repeat count (R=3).

### 3.4 Reentrancy Slice Engine v1

The initial ablation revealed that while `crop_only` achieved the highest accuracy (0.9024), its FPR was elevated (0.458). The cropping logic lacked a **global perspective**—it could not distinguish "important" contracts from "boilerplate" ones, and it stripped the safety context from fixed-variant samples.

We developed `reentrancy_slice_engine.py` with four optimization rules:

**Rule 1 — Precise External Call Filtering**: Only retain low-level calls strongly associated with reentrancy: `call`, `delegatecall`, `callcode` (with `{value:...}` patterns), `transfer`, and `send`. ERC20 `token.transfer` / `transferFrom` are explicitly excluded to reduce noise.

**Rule 2 — Function Filtering**: Slice contracts by `function`/`constructor`/`fallback`/`receive` boundaries. Retain functions with LOC ≥ 5 or containing reentrancy-related external calls. Referenced modifiers are preserved alongside their functions.

**Rule 3 — Significant Function Identification (Top 10%)**: Compute global statistics across all contracts (239 functions → 54 unique names → 5 significant functions meeting criteria: globally unique name + top 10% by length). Contracts are retained only if they contain significant functions or external-call functions.

**Rule 4 — Greedy Block Construction**: Strip comments, imports, and pragmas. Prioritize external-call functions. Greedily fill blocks up to 3,800 characters (the 99th percentile of all sample sizes).

**Compression Effect**: 91,438 total characters → 43,830 characters (47.9% compression); 48/49 samples within the 3,800-character limit. A fallback mechanism ensures no sample is lost even if all contracts are filtered out.

### 3.5 Guard Injection and Prompt Rule Injection

**Problem Discovery**: The slice_v1 experiment revealed that fixed-variant samples were 100% falsely classified as vulnerable (e.g., `03_modifier_fixed`: 3/3 FP with confidence=0.90; `05_cross_contract_fixed`: 3/3 FP with confidence=0.95).

**Root Cause Analysis**: The slicing engine preserved external call patterns but stripped the `ReentrancyGuard` inheritance chain. The model could only see "dangerous call patterns" without the corresponding "protection measures"—in particular, the `nonReentrant` modifier.

**Guard Source Injection**: For contracts using `nonReentrant` / `noReentrant` modifiers, the engine automatically injects the parent `ReentrancyGuard` contract source into the slice. This lets the model "see" the protection mechanism. Result: FPR reduced from 0.458 → 0.375.

**Inline Comment Experiment**: We added explanatory comments within the injected Guard source (e.g., "`locked = true` — this line locks the function"). **This had zero effect on FPR**—the model does not treat code comments as authoritative constraints.

**Prompt Rule Injection**: We injected explicit rules into all 9 prompt templates:
- `nonReentrant` / `noReentrant` modifiers indicate reentrancy protection → NOT a vulnerability
- Mechanism: `locked = true` before function body, `require(!locked)` blocks reentry
- Contract inherits `ReentrancyGuard` + function has `nonReentrant` = safe (fixed)

Result: FPR reduced from 0.375 → **0.250**; fixed-variant accuracy improved from 0.625 → **0.750**.

**Key Design Choice**: We intentionally kept the code unchanged and taught the model through Prompt rules alone. This preserves slice consistency across experiments and directly tests whether prompt engineering can compensate for the model's incomplete Solidity semantic understanding.

---

## 4. Experimental Setup

### 4.1 Dataset

The benchmark comprises 41 curated Solidity smart contract samples drawn from four sources:

| Source | Samples | Positive | Negative | Description |
|---|---|---|---|---|
| `smartbugs_curated` (deduplicated) | 23 | 23 | 0 | Real on-chain reentrancy victims from Etherscan |
| `serial_coder` | 8 | 4 | 4 | Paired insecure/fixed variants × 4 reentrancy types |
| `crosschain_reentrancy_pairs` | 8 | 4 | 4 | Cross-chain paired samples |
| `extra_reentrancy_pocs` | 2 | 2 | 0 | Cross-function and cross-contract PoC samples |
| **Total** | **41** | **33** | **8** | — |

**Data Cleaning**: The original 49-sample dataset contained 8 near-duplicate contracts in `smartbugs_curated` (line-level Jaccard similarity > 90%). After deduplication (31 → 23), re-adding cross-chain pairs, and prefixing `sample_id` with source names to prevent collisions, the final benchmark has 33 positive and 8 negative samples (4.1:1 ratio).

**Four Reentrancy Categories Covered**:

| Category | Pattern Description |
|---|---|
| `standard_reentrancy` | Classic withdraw pattern: external call before balance update |
| `reentrancy_via_modifier` | Vulnerability hidden in modifier; external call occurs before function body |
| `cross_function_reentrancy` | Callback enters a different function in the same contract, bypassing shared state checks |
| `cross_contract_reentrancy` | Main contract → external contract → callback → main contract cycle |

**Label Semantics**: `label=True` indicates the presence of a reentrancy vulnerability (insecure/vulnerable); `label=False` indicates a safe contract (fixed variant).

### 4.2 Evaluation Metrics

We report three core metrics:

- **Accuracy** = (TP + TN) / N — overall correctness, but potentially inflated under class imbalance
- **False Positive Rate (FPR)** = FP / Neg — proportion of safe contracts incorrectly flagged as vulnerable. High FPR → wasted manual audit effort.
- **False Negative Rate (FNR)** = FN / Pos — proportion of actual vulnerabilities missed. High FNR → risk of on-chain asset loss.

In a class-imbalanced setting (33:8), FPR and FNR are more informative than Accuracy alone. We also report **fixed-variant accuracy** to specifically measure the model's ability to recognize protected contracts.

### 4.3 Experimental Protocol

| Parameter | Value | Rationale |
|---|---|---|
| Model | DeepSeek-chat | Cost-effective, OpenAI-compatible API, exposes typical LLM Solidity limitations |
| Temperature | 0 (greedy decoding) | Eliminates sampling variance; differences stem from input, not temperature |
| Repeat count | 3 | Single runs have randomness; mean ± std provides statistical reliability |
| API timeout | 300s | Covers 98% of requests; 1 retry on timeout |
| Slice mode | `risk` / `reentrancy_slice_v1` | Configurable per profile |

All experiments use identical 41 samples, identical T=0, and identical prompt templates. Different `run_id` values isolate experiments without mutual interference.

---

## 5. Results and Analysis

### 5.1 Ablation Study

**Table 1: Ablation experiment results on the cleaned 41-sample benchmark (DeepSeek-chat, T=0, repeat=3, mean values).**

| Profile | Accuracy | FPR | FNR | fixed Acc | Key Finding |
|---|---|---|---|---|---|
| `baseline_raw` | 0.8699 | 0.375 | 0.071 | 0.625 | Pure LLM baseline |
| `crop_only` | **0.9024** | 0.458 | **0.010** | 0.542 | ★ Best Accuracy; near-zero FNR |
| `crop_slither` | 0.8455 | 0.458 | 0.081 | 0.542 | Slither summary degrades performance |
| `crop_slither_cot` | 0.8049 | 0.375 | 0.152 | 0.625 | CoT provides no stable gain |
| `crop_slither_multi` | 0.8049 | 0.542 | 0.111 | 0.458 | ★ Worst: multi-contract context is detrimental |

**Analysis**:

1. **Code cropping is the dominant positive factor**: `crop_only` achieves the highest Accuracy (0.9024) and lowest FNR (0.010), confirming that removing irrelevant code allows the LLM to focus on genuine risk patterns. However, cropping also strips safety context (ReentrancyGuard), elevating FPR to 0.458.

2. **Slither static analysis summaries are counterproductive**: Adding Slither output (`crop_slither`) reduces Accuracy from 0.9024 to 0.8455. The structured static-analysis format appears to interfere with the model's direct code comprehension.

3. **Chain-of-Thought reasoning introduces noise**: The `crop_slither_cot` profile shows no improvement over the baseline. Forcing step-by-step reasoning does not compensate for the model's incomplete understanding of Solidity execution semantics (e.g., the `_` placeholder in modifiers representing function body insertion).

4. **Multi-contract context is actively harmful**: `crop_slither_multi` produces the worst results across all metrics (Accuracy=0.8049, FPR=0.542). More code surfaces more external call patterns, causing the model to over-predict vulnerabilities.

**Marginal contributions** (Acc change relative to previous profile):

```
baseline_raw (0.870)
  → crop_only: +0.033  ← largest positive gain
  → crop_slither: -0.057  ← Slither degrades
  → crop_slither_cot: -0.041  ← CoT degrades further (fixed prompt)
  → crop_slither_multi: 0.000  ← no additional benefit
```

### 5.2 FPR Optimization: Three-Round Iteration

**Table 2: Progressive FPR reduction across optimization rounds.**

| Round | Method | FPR | fixed Acc | Core Finding |
|---|---|---|---|---|
| 1 | Ablation baseline (crop_only) | 0.458 | 0.542 | Cropping strips ReentrancyGuard safety context |
| 2 | + Guard source injection | 0.375 | 0.625 | Model "sees" modifier but doesn't understand it |
| 3 | + Inline explanatory comments | 0.375 | 0.625 | **Code comments are completely ineffective!** |
| 4 | + Prompt rule injection | **0.250** | **0.750** | **System prompt rules are most effective!** |

**Why are inline comments ineffective while Prompt rules work?**

LLMs process inputs through two distinct information channels:
- **Instruction Channel** (system prompt rules): High priority, treated as authoritative constraints
- **Content Channel** (code and comments): Lower priority, treated as contextual documentation

Our experiment empirically validates this distinction in a reentrancy detection context. This has significant implications for LLM prompt engineering in security applications: *telling the model what to believe is more effective than showing it in the data*.

### 5.3 Per-Scenario Analysis

**Table 3: Accuracy breakdown by reentrancy category (best ablation vs. best overall).**

| Category | Ablation Best | slice_v1 + Prompt | Analysis |
|---|---|---|---|
| `standard_reentrancy` | 0.972 | 0.931 | Near-perfect; classic pattern well-learned |
| `cross_function` | 0.833 | **1.000** | Prompt rules achieve zero FP |
| `reentrancy_via_modifier` | 0.800 | 0.800 | Persistent FP (modifier execution order confusion) |
| `cross_contract` | 0.722 | 0.556 | Hardest category; cross-chain patterns deviate from typical reentrancy |

**Fixed-variant confusion evolution**:
- Ablation: 9 FP / 24 fixed → fixed Acc = 0.625
- Guard injection: 9 FP / 24 → fixed Acc = 0.625 (no significant improvement)
- Prompt rules: 6 FP / 24 → fixed Acc = **0.750** (33% FP reduction)

**Persistent false positives** (remaining after all optimizations):
- `03_modifier_fixed`: The `nonReentrant` modifier is recognized by step-0 of the CoT analysis, but the model misjudges modifier execution ordering (when `canReceiveAirdrop` external call occurs relative to `noReentrant` lock).
- Cross-chain `fixed` samples: Non-standard reentrancy patterns (Bridge cross-chain calls) that do not match typical reentrancy templates.

### 5.4 Dataset Cleaning Impact

**Table 4: Comparison of old vs. cleaned datasets (baseline_raw).**

| Metric | Old (37:4) | Cleaned (33:8) |
|---|---|---|
| SmartBugs near-duplicates | 8 | **0** |
| Sample ID collisions | 8 groups | **0** |
| FPR stability | Poor (denominator=4) | **Moderate (denominator=8)** |
| baseline_raw Accuracy | 0.935* | **0.870 (more realistic)** |

*\*Old dataset Accuracy was inflated by near-duplicate samples that artificially boosted apparent performance.*

The cleaned dataset provides more honest performance estimates. However, category imbalance remains (33:8), and cross-chain samples (Acc only 0.556–0.667) may not be suitable as a standard reentrancy detection benchmark due to their distinctive vulnerability patterns.

---

## 6. Discussion

### 6.1 What Works (Validated Gains)

| Method | Evidence | Design Implication |
|---|---|---|
| **Code cropping** | Consistently top-2 Accuracy; largest marginal gain (+0.033) | LLM attention is a scarce resource; noise dilution is the primary threat to detection quality |
| **Guard source injection** | FPR: 0.458 → 0.375 | Letting the model "see" the protection mechanism is necessary but not sufficient |
| **Prompt rule injection** | FPR: 0.375 → 0.250; fixed Acc: 0.625 → 0.750 | System-level instructions carry significantly higher weight than inline code annotations |
| **Dataset cleaning** | Removed 8 near-duplicates; eliminated ID collisions | Data quality checks must precede any experimentation to avoid inflated metrics |

### 6.2 What Does Not Work (No Return on Investment)

| Method | Evidence | Design Implication |
|---|---|---|
| **CoT step-by-step reasoning** | No stable improvement across all experiments | Complex prompts ≠ better results; reasoning chains cannot overcome fundamental semantic understanding gaps |
| **Multi-contract dependency context** | Worst performance across all metrics | More code = more false external-call patterns = increased over-prediction |
| **Inline code comments** | Zero FPR improvement | Models treat comments as documentative context, not as operational constraints |
| **Slither static analysis summaries** | Accuracy degradation (-0.057 from crop_only) | Structured tool output may interfere with the model's direct code comprehension |

### 6.3 Key Insight: Instruction Channel vs. Content Channel

Our experiments reveal a fundamental property of LLM processing in security applications: **LLMs process inputs through two distinct information channels with asymmetric priority**:

1. **Instruction Channel** (system prompt rules): High priority. The model treats these as authoritative constraints that must be followed.
2. **Content Channel** (code text, inline comments): Lower priority. The model treats these as contextual data to be analyzed, not as operational directives.

This discovery has significant implications beyond reentrancy detection: when an LLM lacks domain-specific semantic understanding (e.g., Solidity modifier execution mechanics), *telling it the rule in the system prompt is far more effective than embedding explanations in the data itself*.

### 6.4 Fundamental Limitations

- **Modifier semantics**: DeepSeek-chat has a hard ceiling on understanding Solidity modifier execution semantics—specifically, that `_` in a modifier represents the insertion point of the function body. Even with full source code and explicit rules, modifier-based reentrancy scenarios remain challenging.
- **Class imbalance**: 33 positive vs. 8 negative samples; FPR denominator of only 8 means a single misclassification can measurably affect results.
- **Data leakage risk**: SmartBugs contracts are all Etherscan-verified mainnet contracts, potentially included in LLM pretraining corpora.
- **Sample scale**: 41 samples are suitable for ablation analysis but insufficient for a large-scale benchmark.
- **Zero-shot setting**: All experiments conducted without fine-tuning or few-shot examples.

---

## 7. Conclusion and Future Work

### 7.1 Summary of Contributions

1. **Reproducible detection pipeline**: A complete end-to-end system from data ingestion through preprocessing, prompt assembly, LLM inference, to structured evaluation—with all intermediate artifacts persisted.

2. **Ablation-driven optimization methodology**: Three-round iterative refinement (ablation → slice_v1 + guard → prompt rules) that systematically isolates and validates each enhancement module's contribution.

3. **Empirical validation of instruction-channel priority**: First demonstration in a reentrancy detection context that system prompt rules significantly outperform inline code annotations—a finding with broad implications for LLM-based security analysis.

### 7.2 Final Results

| Method | Accuracy | FPR | FNR | fixed Acc |
|---|---|---|---|---|
| Ablation best (`crop_only`) | **0.9024** | 0.458 | **0.010** | 0.542 |
| `slice_v1` + Guard | **0.9024** | 0.375 | 0.030 | 0.625 |
| `crop_slither` + Prompt | 0.8780 | 0.292 | 0.081 | 0.708 |
| `slice_v1` + Prompt (final) | 0.8699 | **0.250** | 0.101 | **0.750** |

**FPR reduced 45%** (0.458 → 0.250); fixed-variant recognition improved from 54% to 75%.

**Core design takeaways**:
- **Cropping > stacking context**: Removing noise is more effective than adding information.
- **Instructions > annotations**: System prompt rules are strong signals; inline comments are weak signals.
- **Model capability ceilings are real**: DeepSeek-chat's incomplete Solidity semantic understanding cannot be fully compensated through prompt engineering alone.

### 7.3 Future Work

- **Stronger models**: Evaluate GPT-4o and DeepSeek-v4-series to probe the upper bound of Solidity modifier understanding.
- **On-chain validation**: Integrate The DAO, Lendf.Me, and additional verified mainnet contracts into the pipeline.
- **Self-consistency**: Apply multi-sampling with majority voting to improve stability on low-confidence predictions.
- **Dataset expansion**: Acquire more paired fixed/insecure samples (currently only 8 pairs available).
- **RAG exploration**: Implement Retrieval-Augmented Generation as suggested by the benchmark paper (`LLM4Re.pdf`).

---

## Project Structure

```
├── src/
│   ├── main.py                       # Experiment orchestrator (1,046 lines)
│   ├── preprocess.py                 # Slither analysis + code cropping + anonymization
│   ├── reentrancy_slice_engine.py    # 4-rule slice engine + Guard injection
│   ├── run_reentrancy_slice.py       # Batch slice cache generator
│   ├── llm_client.py                 # OpenAI-compatible API client + JSON parser
│   └── chain_contract_test.py        # On-chain case testing (The DAO / Lendf.Me)
├── prompts/                          # 5 prompt templates
│   ├── baseline_prompt.txt           # baseline_raw: full contract source
│   ├── baseline_prompt_paper.txt     # crop_only: cropped code only
│   ├── baseline_summary_prompt.txt   # crop_slither / slice_v1
│   ├── cot_reentrancy_paper.txt      # crop_slither_cot: CoT reasoning
│   └── multi_contract_summary_prompt.txt  # crop_slither_multi: multi-contract
├── contracts/
│   ├── manifest.json                 # Sample ID → file + label mapping
│   ├── dataset_profile.json          # Dataset statistics
│   ├── 02_reentrancy/                # Standard reentrancy pairs
│   ├── 03_reentrancy_via_modifier/   # Modifier reentrancy pairs
│   ├── 04_cross_function_reentrancy/ # Cross-function pairs
│   ├── 05_cross_contract_reentrancy/ # Cross-contract pairs
│   └── smartbugs_curated/            # 23 deduplicated on-chain contracts
├── runs/                             # Key experiment summaries (summary.json + run_config.json)
├── requirements.txt                  # openai, slither-analyzer, langchain-core, pydantic
├── LLM4Re.pdf                        # Reference paper
└── .gitignore
```

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Install Slither (optional but recommended)
pip install slither-analyzer
solc-select install 0.8.17 && solc-select use 0.8.17

# Run ablation experiment
cd src
python3 main.py \
  --backend openai --model deepseek-chat \
  --base-url https://api.deepseek.com \
  --repeat 3 \
  --profiles baseline_raw crop_only crop_slither crop_slither_cot crop_slither_multi \
  --extra-source-root /path/to/extra_reentrancy_pocs \
  --extra-source-root /path/to/crosschain_reentrancy_pairs \
  --run-id my-ablation-experiment

# Run slice_v1 + Prompt rules (final best configuration)
python3 main.py \
  --backend openai --model deepseek-chat \
  --repeat 3 \
  --profiles reentrancy_slice_v1 \
  --slice-mode reentrancy_slice_v1 \
  --extra-source-root /path/to/extra_reentrancy_pocs \
  --extra-source-root /path/to/crosschain_reentrancy_pairs \
  --run-id my-final-experiment
```

---

## References

1. Feist, J., Grieco, G., & Groce, A. (2019). Slither: A Static Analysis Framework for Smart Contracts. *IEEE/ACM 2nd International Workshop on Emerging Trends in Software Engineering for Blockchain (WETSEB)*.

2. LLM4Re: Benchmarking Large Language Models for Smart Contract Reentrancy Detection. See `LLM4Re.pdf`.

---

## License

This project is intended for academic research purposes.
