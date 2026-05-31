# LLM-SmartContract-Reentrancy-Detector

基于 LLM 与静态分析的 Solidity 重入漏洞实验工程。项目围绕实验文档中的 4 类重入样本，提供数据整理、Slither 预处理、代码裁剪、Prompt 组装、批量分析与评估输出。

## 优化后的实验流程

相比“直接把整个合约扔给 LLM”的原始方案，这里采用更稳的五阶段流程：

1. 数据筛选  
   只把 `Insecure*.sol` 与 `Fixed*.sol` 当作评估对象，避免把 `Attack.sol` 和 `Dependencies.sol` 误算为分类样本。  
   对跨函数、跨合约样本，把 `Dependencies.sol` 作为辅助上下文拼接给模型，但不单独计分。

2. 静态预处理  
   优先调用 Slither 提取可能发送 ETH、包含外部调用、读写关键状态变量的函数或修饰器。  
   如果当前机器未正确安装 `slither` 或 `solc`，则自动退化为启发式分析，保证流程在 Windows 上也能先跑通。

3. 结构裁剪  
   保留主合约中与风险直接相关的状态变量定义、风险函数、相关修饰器，以及多合约场景下的依赖接口或守卫合约。  
   这样可以显著减少 Prompt 噪声，让模型更聚焦于外部调用与状态更新顺序。

4. 多策略 Prompt 实验  
   `baseline_raw`：完全只用 LLM 的基准，直接喂完整合约文本。  
   `crop_only`：只做代码裁剪。  
   `crop_slither`：在裁剪基础上加入静态分析摘要。  
   `crop_slither_cot`：再加入分步骤 Prompt Engineering。  
   `crop_slither_multi`：再加入多合约上下文。  
   `fusion`：融合所有改进条件，作为最终版本。  
   旧的 `baseline`、`cot`、`multi_contract` 仍然保留为兼容模式。

5. 自动评估  
   按样本批量输出 `preprocess.json`、`prompt.txt`、`prediction.json` 与 `metrics.json`，并统计 Accuracy、False Positive Rate、False Negative Rate。

## 仓库结构

```text
├── contracts/                      # 精选后的实验样本目录与 manifest
├── external/
│   └── solidity-security-by-example/  # 上游测试集
├── prompts/
│   ├── baseline_prompt.txt
│   ├── baseline_summary_prompt.txt
│   ├── cot_reentrancy_prompt.txt
│   ├── fusion_prompt.txt
│   ├── multi_contract_prompt.txt
│   └── multi_contract_summary_prompt.txt
├── runs/                           # 实验输出
├── src/
│   ├── llm_client.py
│   ├── main.py
│   └── preprocess.py
├── LLM4Re.pdf
├── README.md
└── requirements.txt
```

## 数据集说明

当前实验默认使用 `serial-coder/solidity-security-by-example` 中这四类重入样本：

- `02_reentrancy`
- `03_reentrancy_via_modifier`
- `04_cross_function_reentrancy`
- `05_cross_contract_reentrancy`

每个目录只抽取：

- `Insecure*.sol` 作为正样本
- `Fixed*.sol` 作为负样本
- `Dependencies.sol` 作为辅助上下文

因此，默认评估集共有 8 个主样本。

## 环境准备

建议使用 Python 3.10+。

### 1. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

### 2. 安装 Slither 与 Solidity 编译器

实验推荐 Slither，但它依赖可用的 `solc`。  
在 Linux/macOS 上可优先使用：

```bash
pip install slither-analyzer
solc-select install 0.8.17
solc-select use 0.8.17
```

在 Windows 上，`solc-select` 往往不如 Linux 环境稳定，因此本项目做了双通道设计：

- 正式实验：装好 `slither` + `solc` 后运行，得到更可靠的静态上下文。
- 兜底实验：即使没有 `slither`，也可以先跑启发式预处理与 Prompt 导出。

### 3. 配置 LLM API

如果要真正调用 OpenAI 兼容接口，请设置环境变量：

```bash
set OPENAI_API_KEY=your_api_key
set OPENAI_BASE_URL=https://your-compatible-endpoint/v1
```

如果使用官方 OpenAI，可不设置 `OPENAI_BASE_URL`。

## 运行方式

### 1. 先跑本地启发式基线

这一模式不依赖 API Key，适合先验证数据整理、预处理和评估链路。

```bash
python src/main.py --backend heuristic
```

运行后会自动：

- 把 4 类样本整理到 `contracts/`
- 为每个样本生成预处理结果与 Prompt
- 用本地启发式规则给出一个可复现的弱基线
- 在 `runs/` 下输出各 profile 的指标和对比报告

如果要跑真正的对比实验流程，直接跑默认 ablation ladder：

```bash
python src/main.py --backend heuristic
```

如果想显式指定这条 ablation ladder，也可以写出来：

```bash
python src/main.py --backend heuristic --profiles baseline_raw crop_only crop_slither crop_slither_cot crop_slither_multi fusion
```

如果还想跑旧版兼容模式，可以切回 legacy prompt families：

```bash
python src/main.py --backend heuristic --strategies baseline cot multi_contract
```

### 2. 跑正式 LLM 实验

```bash
python src/main.py --backend openai --model gpt-4o-mini
```

### 3. 仅做冒烟测试

```bash
python src/main.py --backend heuristic --max-samples 2 --strategies baseline
```

## 输出结果

每次运行后，`runs/<profile>/<sample_id>/` 下会包含：

- `preprocess.json`：静态分析与裁剪结果
- `prompt.txt`：最终发送给模型的 Prompt
- `prediction.json`：模型或启发式预测结果

同时：

- `runs/<profile>/run_spec.json`：该轮 profile 的具体配置
- `runs/<profile>/metrics.json`：单 profile 指标
- `runs/summary.json`：所有 profile 汇总指标
- `runs/comparison.json`：相对 `baseline_raw` 的差值对比

## 当前实现说明

- `src/preprocess.py`  
  负责 Slither 优先的静态信息提取、启发式兜底、相关代码裁剪与多文件上下文组装。

- `src/llm_client.py`  
  封装 OpenAI 兼容调用，并将模型输出解析为结构化 JSON 预测。

- `src/main.py`  
   负责整理样本、生成 Prompt、批量调用后端、计算 Accuracy/FPR/FNR，并生成 ablation 对比报告。

- Prompt 组装前会对样本编号、文件名和带标签倾向的合约命名做匿名化，避免 Fixed / Insecure 之类的命名泄漏到模型输入。

## 建议实验记录方式

为了形成课程实验报告，建议你记录以下对比：

1. 先看 `baseline_raw`，它是“完全只使用 LLM”的基准线。
2. 再看 `crop_only`，判断代码裁剪是否单独带来收益。
3. 再看 `crop_slither`，判断静态分析摘要是否有效。
4. 再分别看 `crop_slither_cot` 和 `crop_slither_multi`，判断 Prompt Engineering 和多合约上下文各自的贡献。
5. 最后看 `fusion`，确认所有改进叠加后是否达到最好或最稳的结果。
6. 比较时优先看 `comparison.json` 里每个 profile 相对 `baseline_raw` 的 delta，再结合 `metrics.json` 看绝对值。

## 可扩展方向

- 补充 Etherscan 主网对照合约并加入 `contracts/real_world/`
- 使用更细粒度的 Solidity 解析器替代正则裁剪
- 为 LLM 输出增加 self-consistency 或多轮审计投票
- 将 Slither detector 输出与 CFG 信息合并进 Prompt
