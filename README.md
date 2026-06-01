# LLM-Based Smart Contract Reentrancy Detection

> 基于 DeepSeek-chat 的智能合约重入漏洞检测实验工程
>
> 完整实验流水线：数据清洗 → 静态分析 → 代码裁剪 → Prompt 组装 → LLM 预测 → 评估

---

## 项目概述

本项目复现并扩展了基于 LLM 的重入漏洞检测方法。通过**消融实验**逐层验证每个技术模块的真实贡献，并发现：代码裁剪是关键增益模块，而 CoT 思维链和多合约上下文在重入检测场景中没有稳定帮助。

最终方案（reentrancy_slice_v1 + Prompt 规则注入）实现了 **FPR 从 0.458 降至 0.250（下降 45%），fixed 变体识别率从 54% 升至 75%**。

---

## 实验设计思路（三轮迭代）

### 第 1 轮：消融实验 —— "谁才是真正有用的模块？"

**动机**：端到端黑盒无法定位收益来源，必须逐层剥离验证。

5 个 profile 从简单到复杂递进：

```
baseline_raw (全量源码)
    → crop_only (仅裁剪代码)
    → crop_slither (裁剪 + Slither 静态摘要)
    → crop_slither_cot (裁剪 + 摘要 + CoT 分步推理)
    → crop_slither_multi (裁剪 + 摘要 + CoT + 多合约上下文)
```

**关键发现**：
- **crop_only Acc 最高 (0.9024)**：去掉噪声让 LLM 聚焦 → 但裁剪同时也剥离了 ReentrancyGuard 安全上下文 → FPR 高达 0.458
- **crop_slither Acc 下降 (0.8455)**：Slither 摘要反而干扰判断
- **crop_slither_cot/crop_slither_multi**：CoT 和多合约上下文始终没有稳定增益
- **结论**：裁剪 > 一切；Slither/CoT/Multi 都是噪声

### 第 2 轮：Slice v1 + Guard 注入 —— "让模型看到保护锁"

**动机**：第 1 轮发现裁剪导致 fixed 变体全被误判 → 需要更精准的裁剪 + 补回安全上下文。

设计了 **reentrancy_slice_v1** 切片引擎，4 条核心规则：

| 规则 | 内容 | 目的 |
|---|---|---|
| 规则 1 | 只保留 call/delegatecall/callcode+value, transfer/send（排除 ERC20） | 精确化外部调用 |
| 规则 2 | 函数 LOC ≥ 5 或含外部调用才保留 | 过滤空函数和 getter |
| 规则 3 | 全局统计 → 显著函数 Top 10%（全局唯一名 + 长度前 10%） | 跨合约重要函数识别 |
| 规则 4 | 贪心填充到 3800 字符（p99） | 控制 Prompt 长度 |

同时注入 **ReentrancyGuard 源码**：检测 nonReentrant 修饰符 → 自动将父合约的 Guard 源码插入切片。

**结果**：Acc 持平 crop_only (0.9024)，FPR 从 0.458 → 0.375。

### 第 3 轮：Prompt 规则注入 —— "从看到到理解"

**动机**：Guard 注入后 FPR 仍 0.375 → 模型"看到" nonReentrant 源码但不理解 modifier 语义。

**假设**：LLM 对"系统指令"的感知权重大于"代码注释"。

**方案**：在所有 9 个 Prompt 模板中注入：
- `nonReentrant` / `noReentrant` 修饰符 = 重入保护锁
- 执行前 `locked=true` + `require(!locked)` → 回调被阻止
- 合约继承 `ReentrancyGuard` + 函数带 `nonReentrant` → safe

同时试验了**代码内注释**（在 Guard 源码中加 "此行是上锁操作" 注释）→ **完全无效**，验证了"指令通道 ≠ 内容通道"的假设。

**最终结果**：FPR 从 0.375 → **0.250**（再降 33%），fixed Acc 从 0.625 → **0.750**。

---

## 完整实验结果

| 实验 | Acc | FPR | FNR | fixed Acc | 说明 |
|---|---|---|---|---|---|
| baseline_raw | 0.8699 | 0.375 | 0.071 | 0.625 | 全量代码基线 |
| crop_only | **0.9024** | 0.458 | **0.010** | 0.542 | ★ Acc 最优，几乎不漏 |
| crop_slither | 0.8455 | 0.458 | 0.081 | 0.542 | Slither 帮倒忙 |
| crop_slither_cot | 0.8049 | 0.375 | 0.152 | 0.625 | CoT 无增益 |
| crop_slither_multi | 0.8049 | 0.542 | 0.111 | 0.458 | ★ 最差，多文件害了 |
| slice_v1 + Guard | 0.9024 | 0.375 | 0.030 | 0.625 | 裁剪+Guard源码 |
| crop_slither + Prompt | 0.8780 | 0.292 | 0.081 | 0.708 | Prompt 规则有效 |
| **slice_v1 + Prompt** | 0.8699 | **0.250** | 0.101 | **0.750** | ★ **FPR 最优，综合最优** |

> 所有实验：DeepSeek-chat, T=0, repeat=3 均值, 41 样本 (33正/8负)

---

## 项目结构

```
├── external/                         # 原始数据（4 个数据源）
│   ├── solidity-security-by-example/ # 8 个配对样本 (4类×insecure+fixed)
│   ├── smartbugs-curated/            # 23 个去重后链上重入合约
│   ├── extra_reentrancy_pocs/        # 2 个 PoC 样本
│   └── crosschain_reentrancy_pairs/  # 8 个跨链配对样本
│
├── contracts/                        # 精选合约 + manifest.json
│   └── manifest.json                 # 样本 ID → Solidity 文件 + 标签映射
│
├── contracts_reentrancy_slice_v1/    # 预计算切片缓存
│
├── prompts/                          # 9 个 Prompt 模板
│   ├── baseline_prompt.txt           # baseline_raw：全量代码
│   ├── baseline_prompt_paper.txt     # crop_only：仅裁剪代码
│   ├── baseline_summary_prompt.txt   # crop_slither / slice_v1
│   ├── cot_reentrancy_paper.txt      # crop_slither_cot：CoT 分步推理
│   ├── multi_contract_summary_prompt.txt  # crop_slither_multi：多合约上下文
│   └── ...（4 个旧版兼容模板）
│
├── src/                              # 核心代码（6 个文件）
│   ├── main.py                       # 实验编排主入口
│   ├── preprocess.py                 # 预处理：Slither + 代码裁剪 + 匿名化
│   ├── reentrancy_slice_engine.py    # 切片引擎 v1：4 条规则 + Guard 注入
│   ├── run_reentrancy_slice.py       # 切片批量生成
│   ├── llm_client.py                 # LLM API 调用 + JSON 解析
│   └── chain_contract_test.py        # 链上案例测试 (The DAO / Lendf.Me)
│
├── runs/                             # 所有实验输出
│   ├── deepseek-ablation-clean-r3-20260601/  # 第1轮：消融实验
│   ├── deepseek-slice-v1-guard-r3-20260601/  # 第2轮：Guard 注入
│   └── deepseek-promptfixed-r3-20260601/     # 第3轮：Prompt 规则
│
├── requirements.txt                  # Python 依赖
└── LLM4Re.pdf                        # 参考论文
```

---

## 数据集说明

### 来源

| 来源 | 样本数 | 阳性 | 阴性 | 说明 |
|---|---|---|---|---|
| smartbugs_curated (去重) | 23 | 23 | 0 | Etherscan 真实被攻击合约，90% Jaccard 去重 |
| serial_coder | 8 | 4 | 4 | 4 类重入 × (insecure + fixed) 配对 |
| crosschain_reentrancy_pairs | 8 | 4 | 4 | 跨链场景配对样本 |
| extra_reentrancy_pocs | 2 | 2 | 0 | 跨函数/跨合约 PoC |
| **合计** | **41** | **33** | **8** | — |

### 四类重入覆盖

| 类别 | 样本来源 |
|---|---|
| standard_reentrancy | 经典 withdraw 模式：先 call 后减余额 |
| reentrancy_via_modifier | 漏洞藏在 modifier 中，外部调用在函数体前 |
| cross_function_reentrancy | 回调进入同合约另一函数，共享状态被绕过 |
| cross_contract_reentrancy | 主合约→外部合约→回调→主合约 |

### 标签语义

- `label=True` → 存在重入漏洞 (insecure / vulnerable)
- `label=False` → 安全 (fixed 变体)

---

## 环境准备

### 1. Python 依赖

```bash
pip install -r requirements.txt
```

### 2. Slither（可选但推荐）

```bash
pip install slither-analyzer
solc-select install 0.8.17
solc-select use 0.8.17
```

> 若未安装 Slither，预处理会自动降级为启发式分析（正则规则）。

### 3. LLM API Key

```bash
export OPENAI_API_KEY=your_api_key
# 若使用 DeepSeek：
# export OPENAI_API_KEY=sk-xxx
# export OPENAI_BASE_URL=https://api.deepseek.com
```

---

## 运行方式

### 消融实验（5 profile × repeat=3）

```bash
cd src
python3 main.py \
  --backend openai \
  --model deepseek-chat \
  --base-url https://api.deepseek.com \
  --repeat 3 \
  --profiles baseline_raw crop_only crop_slither crop_slither_cot crop_slither_multi \
  --extra-source-root /opt/uestc/external/extra_reentrancy_pocs \
  --extra-source-root /opt/uestc/external/crosschain_reentrancy_pairs \
  --run-id deepseek-ablation-v1
```

### 切片 v1 + Guard 注入实验

```bash
python3 main.py \
  --backend openai --model deepseek-chat \
  --repeat 3 \
  --profiles reentrancy_slice_v1 \
  --slice-mode reentrancy_slice_v1 \
  --extra-source-root /opt/uestc/external/extra_reentrancy_pocs \
  --extra-source-root /opt/uestc/external/crosschain_reentrancy_pairs \
  --run-id deepseek-slice-guard-v1
```

### Prompt 规则注入实验

```bash
python3 main.py \
  --backend openai --model deepseek-chat \
  --repeat 3 \
  --profiles reentrancy_slice_v1 crop_slither \
  --slice-mode reentrancy_slice_v1 \
  --extra-source-root /opt/uestc/external/extra_reentrancy_pocs \
  --extra-source-root /opt/uestc/external/crosschain_reentrancy_pairs \
  --run-id deepseek-prompt-v1
```

### 只用启发式后端（快速验证数据链路）

```bash
python3 main.py --backend heuristic --repeat 3
```

### 小范围冒烟测试

```bash
python3 main.py --backend openai --max-samples 5 --repeat 1
```

### 预计算切片缓存（可选，加速后续实验）

```bash
python3 run_reentrancy_slice.py
```

---

## 输出结构

每次运行后在 `runs/<run_id>/` 下：

```
runs/<run_id>/
├── run_config.json           # 实验配置快照
├── summary.json              # 汇总指标 (Acc/FPR/FNR 均值±标准差)
├── comparison.json           # 与 baseline_raw 的对比
├── error_analysis.md         # 错误样本详细分析
├── repeat_1/
│   ├── baseline_raw/
│   │   ├── sample_01/preprocess.json   # 预处理结果
│   │   ├── sample_01/prompt.txt        # 发送给 LLM 的 Prompt
│   │   └── sample_01/prediction.json   # LLM 的结构化预测
│   └── crop_only/...
├── repeat_2/...
└── repeat_3/...
```

---

## 核心代码说明

| 文件 | 功能 | 核心函数 |
|---|---|---|
| `src/main.py` | 实验编排主入口 | `main()` → 数据加载 → 遍历 repeat×profile → 评估 |
| `src/preprocess.py` | Slither 静态分析 + 代码裁剪 + 匿名化 | `preprocess_contract()` |
| `src/reentrancy_slice_engine.py` | 切片引擎 v1：4 条规则 + Guard 注入 | `build_slice_block()` |
| `src/llm_client.py` | OpenAI 兼容 API 调用 + JSON 解析 | `OpenAICompatibleClient.predict()` |
| `src/run_reentrancy_slice.py` | 批量生成切片缓存 | `main()` |

### Prompt 组装流程

```
Solidity 源码
    ↓ preprocess_contract() — 静态分析 + 代码裁剪
PreprocessResult（裁剪文本 + 静态发现 + 安全上下文）
    ↓ 填充 Prompt 模板占位符 ({code_context}, {static_summary}...)
完整 Prompt 文本
    ↓ LLM 调用 (T=0, 300s timeout)
JSON 结构化预测
    ↓ parse_prediction() — 提取 is_vulnerable, vulnerability_type 等
评估指标
```

---

## 关键发现总结

### ✅ 有效的方法

1. **代码裁剪** — 去掉无关代码是最大增益，LLM 注意力是稀缺资源
2. **Guard 源码注入** — FPR 0.458 → 0.375，让模型 "看到" 保护锁
3. **Prompt 规则教授** — FPR 0.375 → 0.250，系统指令 > 代码注释
4. **数据集清洗** — 去重 8 个近重复样本，FPR 评估更可靠

### ❌ 无效或退化

1. **CoT 分步推理** — 所有实验中无稳定增益
2. **多合约上下文** — FPR 反而升至 0.542
3. **解释性代码注释** — "locked=true 上锁" 对模型完全无效
4. **Slither 静态摘要** — 信息格式干扰模型对代码本身的理解

### 💡 核心洞察

> LLM 处理输入时有两条信息通道：**指令通道**（系统 Prompt，优先级高）和 **内容通道**（代码与注释，优先级低）。本实验首次在重入检测场景下验证了这一机制。

---

## 局限性

- 类别不平衡（33正:8负），FPR 分母仅 8
- DeepSeek-chat 对 Solidity modifier 执行语义理解有明确上限
- 公开数据泄漏风险（smartbugs 合约都在 Etherscan 已验证）
- 样本规模有限（41 个适合消融，非大规模 benchmark）
- 所有实验均为 zero-shot，未微调

## 未来方向

- 更强模型（GPT-4o, DeepSeek-v4）验证 modifier 语义理解的上限
- 链上真实合约验证（The DAO, Lendf.Me）
- Self-consistency 投票机制
- 扩展 paired fixed/insecure 样本
- RAG 检索增强方案

---

## 许可证

This project is for academic research purposes.
