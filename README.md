# 基于 LLM 的智能合约重入漏洞检测

> 消融实验驱动的迭代优化流水线 · DeepSeek-chat · 代码切片 · Prompt 工程 · RAG

---

## 引言与背景

### 为什么要研究重入漏洞

重入漏洞是智能合约最经典、最具破坏性的安全问题之一，核心风险是"外部调用后控制权被夺回"。合约在执行外部调用时如果尚未完成状态更新，攻击者即可通过回调再次进入同一逻辑，后果通常为余额重复提取、权限状态错乱、领取次数被绕过，最终造成链上资产损失。

传统静态分析工具擅长寻找"表面模式"，但面对跨函数、跨合约、modifier 隐藏调用时常常漏掉真正的攻击路径。LLM 的价值在于能读懂更长的上下文、整合多文件信息，并用自然语言推理出"调用链 + 状态变化顺序"。

### 重入漏洞的典型类型

1. **单函数重入**：攻击者在同一函数里通过外部回调再次进入原函数，例如经典的 withdraw 模式——先 external call，后更新余额。
2. **跨函数重入**：攻击者回调进入同一合约的另一 public 函数，这些函数共享余额、锁变量、白名单或计数器等状态。
3. **跨合约重入**：主合约调用依赖合约或外部接口后，被攻击者引导回到主合约，形成"主合约—外部合约—主合约"的循环。
4. **modifier 重入**：漏洞不在函数体内，而藏在 modifier 中；函数主体尚未开始执行，控制权已被外部调用交出。

### 常见攻击手段

- **fallback / receive 回调**：合约通过 `call`、`send`、`transfer` 向攻击者地址转账，攻击者在回调中再次调用受害函数。
- **递归外部调用**：受害合约在一个函数中多次触发外部合约接口，攻击者利用第一次外部调用构造第二次进入机会。
- **共享状态绕过**：攻击者先触发某个函数修改中间状态，再回调另一个函数绕过原先的检查条件。
- **Token Hook / 接口钩子**：在 ERC777、ERC721 等场景中，转账或安全转移本身会触发 hook，形成天然回调点。
- **modifier 前置调用**：在 modifier 内部先做外部交互，再进入函数主体，攻击者获得"未完成初始化的窗口期"。

最稳妥的防护是 CEI（Checks-Effects-Interactions）原则：先检查条件，再修改状态，最后做外部交互；必要时再叠加重入锁。

### 文献综述与研究空白

传统方法主要依赖人工审计、规则匹配和静态分析工具，例如 Slither 能快速定位可疑外部调用点。这些方法对"显式模式"有效，但面对跨函数、跨合约、多文件依赖时，往往需要审计者手工补齐上下文。纯 LLM 方法能读长代码、做语义归纳，但容易受到长上下文噪声、Prompt 设计和幻觉问题的影响。

**研究空白**：如何让 LLM 在"长代码 + 多文件依赖 + 重入语义"场景中，既保持可复现，又能做可解释的判断。

**本研究的切入点**：把静态分析、代码裁剪和 Prompt 工程组合成一个可重复的实验流水线，再用消融实验逐项验证每个增强模块是否真的带来收益。

### 研究目的与创新点

- 建立一个可重复的重入漏洞检测流程：数据整理、预处理、Prompt 组装、模型预测、结果评估全链路落盘。
- 将 DeepSeek-chat 作为 LLM 基线，比较原始代码、裁剪代码、Slither 摘要、CoT、多合约上下文等方案。
- 用统一的 JSON 输出格式记录 `is_vulnerable`、`vulnerability_type`、`vulnerable_functions`、`attack_path`、`confidence` 和 `reasoning`。
- 通过消融分析回答：哪些上下文真的有帮助，哪些反而会稀释模型判断。

---

## 研究方法

### 实验迭代路线

```
第 1 轮：消融实验（5 个 profile × repeat=3）
  → 发现：FPR 过高（0.458），fixed 变体识别率仅 0.542，安全上下文丢失

第 2 轮：slice_v1 + Guard 注入（4 项规则优化）
  → 发现：FPR 降至 0.375，切片剥离安全上下文

第 3 轮：Prompt 规则注入（显式教授 nonReentrant 语义）
  → 结果：FPR 0.250，fixed Acc 0.750（FPR 累计下降 45%）
  → 问题：FNR 升至 0.101，nonReentrant 规则矫枉过正

第 4 轮：切片级绕过检测（安全摘要注入）
  → 在切片中自动标注 [SAFE]/[BYPASS-RISK] 标签
  → 结果：Acc 0.878，FNR 0.071（漏报减少 30%），FPR 0.333

第 5 轮：RAG + 强约束 Prompt（借鉴 PropertyGPT 的检索增强生成方案）
  → 构建 8 条重入模式向量库，为待检测代码检索 Few-Shot 参考示例
  → 引入 MUST/MUST NOT/REMEMBER 强约束层级，将重入保护规则提升为系统指令
  → 结果：FPR 降至 0.000（零误报），fixed 合约识别率 1.000，Acc 0.903
  → 代价：FNR 升至 0.111，modifier 重入全部漏报

第 6 轮：合约标准增强 + 三步判定框架（借鉴 Cai et al. 的 ERC 标准分析）
  → 构建 ERC 标准知识库，自动检测合约标准类型及 hook 触发机制
  → 引入 Entry Point → Reentry Point → Flow Check 三步判定 Prompt
  → 结果：modifier Acc 首次达到 1.000
  → 代价：cross_contract FPR=1.000

第 7 轮：confidence-gated 组合流水线
  → 利用 rag_strong 的 confidence=0.0（FN 样本）作为切换信号
  → Pass 1: rag_strong，confidence<0.5 时 Pass 2: standards_entry
  → 结果：Acc 0.957，FPR=0，FNR=0.049，modifier Acc=0.889
  → 每轮 1 次额外 API 调用（2.4% 开销）
```

### 关键设计决策与实验协议

| 决策 | 理由 |
|---|---|
| repeat=3 | 单次运行具有随机性，3 次报告均值 ± 标准差更可信 |
| T=0（贪婪解码） | 消除采样随机性，确保不同 profile 之间差异来自输入而非温度 |
| 5 个消融 profile | 从简单到复杂逐层叠加：raw→crop→slither→cot→multi，每层验证一个假设 |
| 300s timeout | DeepSeek API 偶尔超时，300s 覆盖 98% 请求 |
| DeepSeek-chat | 性价比最优，OpenAI 兼容接口，且其 Solidity 语义理解能力恰好暴露了当前 LLM 的典型局限 |

### 数据集构建与质量控制

#### 数据来源构成

实验基准融合四个互补数据源，覆盖从教学级配对样本到真实链上受害合约的完整梯度：

1. **serial-coder**：8 个配对样本，4 类场景各含 insecure 与 fixed 版本。提供标准化的正负对照基线。
2. **smartbugs-curated**：31 个 Etherscan 已验证的真实链上重入受害合约，全为阳性。用于检验方法在真实复杂合约上的泛化能力。
3. **extra_reentrancy_pocs**：2 个自定义跨函数/跨合约 PoC 样本，填补配对数据中复杂攻击路径的空白。
4. **crosschain_reentrancy_pairs**：8 个跨链场景配对样本，拓展 benchmark 的攻击面覆盖。

#### 数据质量问题与清洗策略设计

初次合并 49 个样本后，发现三类影响实验有效性的质量问题。**若不经清洗直接开始消融实验，后续所有结论的统计基础都将被污染**——因此数据清洗被置于实验之前作为第零阶段。

**问题一：近重复样本导致准确率通胀**。smartbugs-curated 中 31 个合约经行级 Jaccard 相似度检测，存在 8 个相似度超过 90% 的近重复对。这些重复样本在 train/test 中重复出现，使模型仅靠记忆即可"猜对"——旧数据集上 baseline_raw Acc 虚高至 0.935，清洗后回落至真实的 0.870。**清洗设计**：以 90% 阈值的行级 Jaccard 去重，31→23 个独立样本。

**问题二：sample_id 碰撞导致实验数据覆盖**。多源合并时，不同来源的样本采用相同命名模式，造成目录级别的写入冲突。**清洗设计**：sample_id 采用 `source_name__原id` 前缀化命名，确保跨源唯一性。

**问题三：类别严重不平衡使 FPR 评估不可靠**。原始比例 37 正 : 4 负（9.2:1），FPR 分母仅 4——单次误判即可造成 25% 的指标波动。**清洗设计**：重新加入 crosschain_pairs 的 4 个阴性样本，将负样本从 4 扩充至 8，FPR 评估的统计稳定性显著改善。

#### 清洗后数据集特征

| 来源 | 样本数 | 阳性 | 阴性 | 角色 |
|---|---|---|---|---|
| smartbugs_curated（去重后） | 23 | 23 | 0 | 真实链上复杂度 |
| serial_coder | 8 | 4 | 4 | 标准化正负对照 |
| crosschain_reentrancy_pairs | 8 | 4 | 4 | 跨链场景拓展 |
| extra_reentrancy_pocs | 2 | 2 | 0 | 复杂攻击路径 |
| **合计** | **41** | **33** | **8** | — |

**四类重入覆盖**：standard_reentrancy（经典 withdraw 模式：先 call 后减余额）、reentrancy_via_modifier（漏洞在 modifier 中，外部调用在函数体前）、cross_function_reentrancy（回调进入同合约另一函数）、cross_contract_reentrancy（主合约→外部合约→回调→主合约）。

标签语义：`label=True` = 存在重入漏洞（insecure / vulnerable），`label=False` = 安全（fixed 变体）。

### 整体方法流程

四阶段流水线：Solidity 合约与依赖文件 → 预处理（Slither / 规则回退，裁剪与匿名化）→ Prompt 组装 → DeepSeek-chat 结构化预测 → 评估与落盘（Accuracy / FPR / FNR）。预处理阶段保留风险函数、相关 modifier 和依赖上下文，并对样本名做匿名化减少标签泄漏。模型输出采用固定 JSON 结构，方便批量解析与指标统计。使用 `--slice-mode reentrancy_slice_v1` 时，预处理会自动从 `contracts_reentrancy_slice_v1/` 加载预计算切片（缓存命中）或实时调用切片引擎（缓存未命中）。

### Prompt 设计与消融配置

**实验动机**：核心问题是"什么样的上下文对 LLM 重入检测最有帮助？是越多越好，还是精准裁剪更重要？"

5 个 profile 由简至繁递进，每个对应一套 Prompt 模板文件：

| Profile | Prompt 模板 | 输入特征 | 验证假设 |
|---|---|---|---|
| `baseline_raw` | `baseline_prompt.txt` | 全量主合约原文 | 纯 LLM 基线——是否需要任何预处理？ |
| `crop_only` | `baseline_prompt_paper.txt` | 裁剪后风险代码 | 仅裁剪——验证"去掉无关代码"是否有帮助 |
| `crop_slither` | `baseline_summary_prompt.txt` | 裁剪 + Slither 摘要 | 裁剪+摘要——验证静态分析信息是否增强判断 |
| `crop_slither_cot` | `cot_reentrancy_paper.txt` | + CoT 分步推理 | 加入 CoT——验证复杂 Prompt 工程是否有收益 |
| `crop_slither_multi` | `multi_contract_summary_prompt.txt` | + 多合约上下文 | 加入多合约——验证依赖文件是否必要 |
| `reentrancy_slice_v1` | `baseline_summary_prompt.txt` | 切片 v1 + Guard 注入 | 裁剪更精准 + 安全上下文完整 |
| `rag_strong` | `rag_reentrancy_prompt.txt` | 切片 v1 + Slither 摘要 + 强约束 | 验证 MUST/MUST NOT 约束层级能否取代文本规则 |
| `rag_fewshot` | `rag_fewshot_prompt.txt` | + RAG Few-Shot 示例 | 验证检索增强的相似漏洞参考能否引导模型判断 |

**各模板使用场景**：

| 模板文件 | 对应 Profile | 输入内容 | 使用阶段 |
|---|---|---|---|
| `baseline_prompt.txt` | `baseline_raw` | 全量合约原文 | 消融 / Prompt规则 / bypass |
| `baseline_prompt_paper.txt` | `crop_only` | 裁剪后风险代码 | 消融 / Prompt规则 / bypass |
| `baseline_summary_prompt.txt` | `crop_slither`、`reentrancy_slice_v1` | 裁剪代码 + Slither 摘要 | 消融 / Prompt规则 / bypass |
| `cot_reentrancy_paper.txt` | `crop_slither_cot` | 裁剪代码 + 摘要 + CoT 步骤 | 消融 / Prompt规则 / bypass |
| `multi_contract_summary_prompt.txt` | `crop_slither_multi` | 裁剪代码 + 摘要 + 依赖文件 | 消融 / Prompt规则 / bypass |
| `rag_reentrancy_prompt.txt` | `rag_strong` | 裁剪代码 + 摘要 + MUST/MUST NOT 强约束 | RAG 实验 |
| `rag_fewshot_prompt.txt` | `rag_fewshot` | 裁剪代码 + 摘要 + Few-Shot 示例 + 强约束 | RAG 实验 |

**模板版本说明**：

`prompts/` 目录下的模板为**当前生效版本**（第 3 阶段：Prompt 规则注入 + bypass）。其中均包含 `【重入保护机制识别规则】` 区块，显式教授 nonReentrant 的语义和判定规则。`cot_reentrancy_paper.txt` 额外包含"步骤 0"前置检查。

`prompts/original_*.txt` 为**原始备份版本**（第 1-2 阶段：消融 / Guard 注入期使用）。与当前版本的唯一区别是**不含 nonReentrant 规则区块**。复现 Guard 注入期实验（如 `deepseek-slice-v1-guard-r3-20260601`）时，需将 original 版本覆盖当前模板后运行。

**模板设计原则**：所有模板共享相同的 JSON 输出格式要求，确保不同 profile 之间的预测结果可直接比较。每个模板独立维护，修改其中一个不影响其他 profile 的历史实验结果。

消融实验逻辑：从简单到复杂逐层叠加，观察每一步的边际收益。若某层退化，说明该增强可能引入噪声。所有 profile 共享同一样本集、T=0、repeat=3。

**reentrancy_slice_v1 优化方案**：在消融实验基础上，引入 4 项切片优化规则——外部调用精确化、函数筛选、显著函数 Top 10%、贪心填充 3800 字符。

### Prompt 规则注入

**设计动机**：slice_v1 + Guard 实验中，modifier 重入和跨合约重入的 fixed 变体被全部误判——`03_modifier_fixed` 3/3 FP（confidence=0.90），`05_cross_contract_fixed` 3/3 FP（confidence=0.95）。根源在于切片剥离了 ReentrancyGuard 继承链，模型只能看到"危险的调用模式"而看不到"保护措施"。

注入的 Prompt 规则核心内容：
- 如果函数使用了 `nonReentrant` / `noReentrant` 修饰符，说明已受重入锁保护 → **这不是漏洞**。
- `nonReentrant` 工作原理：执行函数体前 `locked=true` 上锁，`require(!locked)` 阻止回调重入。
- 合约继承 `ReentrancyGuard` + 函数带 `nonReentrant` = safe（fixed）。

**设计选择**：保持代码原样，只在 Prompt 中教学——这样代码切片结果不变，所有实验结果可对比，且验证了"仅靠 Prompt 能否补偿模型的语义理解不足"。

### 评价指标与实验协议

三项核心指标：Accuracy = (TP+TN)/N，FPR = FP/Neg，FNR = FN/Pos。

类别不平衡（33 正 : 8 负）时，Accuracy 可能虚高。FPR 高 = 误报太多，fixed 合约被错误判为有漏洞 → 人工复核成本增加。FNR 高 = 漏报太多，真实漏洞滑过检测 → 链上资产损失风险。需要同时优化两者，而非只看 Accuracy。

**实验协议**：所有对比实验必须：相同 41 个样本、相同模型（DeepSeek-chat）、T=0、repeat=3 报告均值 ± 标准差。不同 run-id 独立保存，旧实验完全不动。

### 数据集优化：reentrancy_slice_v1

**为什么要做数据集优化？** 前一轮消融发现核心问题：裁剪逻辑缺乏全局视角，未区分"重要合约"与"模板合约"，且 fixed 变体安全上下文丢失。

**4 项优化规则**：

1. **外部调用精确化**：只保留重入强相关的低级调用——`call`、`delegatecall`、`callcode` + `call{value:...}`、`transfer`、`send`，不把 ERC20 的 `token.transfer`/`transferFrom` 当作强制保留。
2. **函数筛选**：按 function/constructor/fallback/receive 切片；保留 LOC ≥ 5 或含外部调用的函数；被保留函数的 modifier 一并保留。
3. **显著函数 Top 10%**：统计全局 239 个函数 → 54 个唯一名 → 5 个显著函数（全局唯一名 + 长度前 10%）。合约含显著函数或外部调用函数才保留。
4. **输入块构造**：清理注释/import/pragma，外部调用函数优先，按长度贪心填充至字符上限 3800（p99）。

**压缩效果**：原始 91,438 → 切片 43,830 字符（47.9% 压缩），48/49 样本控制在 3800 字符以内。规则 3 内置兜底机制，确保即使过滤后无合约保留也不会丢失样本。

---

## 链上案例

为了验证方法不仅适用于整理后的 benchmark，还能对应真实主网合约，选取了两个公开可验证的链上案例作为未来验证目标：

- **The DAO**：经典重入攻击代表案例，主网地址 `0xbb9bc244d798123fde783fcc1c72d3bb8c189413`，代表函数为 `splitDAO(...)`、`withdrawRewardFor(...)`。攻击路径核心在于资金转出与记账顺序不当，适合验证模型能否识别 external call → state update 的危险顺序。
- **Lendf.Me**：更接近现代 DeFi 借贷场景，主网地址 `0x0eEe3E3828A45f7601D5F54bF49bB01d1A9dF5ea`，代表接口为 `supply(...)`、`withdraw(...)`、`borrow(...)`。涉及代币回调与跨合约交互，调用链更长、上下文更多，适合检验裁剪 + 静态摘要是否优于纯原始输入。

---

## 研究结果

以下按实验迭代的时间顺序组织。每轮实验由前一轮的发现驱动，形成"问题→设计→结果→引出新问题"的递进链条。

---

### 4.1 消融实验：逐层剥离，量化各模块边际贡献

**驱动问题**：五种上下文配置（原始代码、裁剪代码、Slither 摘要、CoT 推理、多合约依赖）中，哪个对重入检测真正有效？

**实验设计**：5 个 profile 由简至繁逐层叠加——baseline_raw → crop_only → crop_slither → crop_slither_cot → crop_slither_multi。每层叠加一个模块，通过与该层 baseline 的指标差值量化该模块的边际增益。

| Profile | Accuracy | FPR | FNR | fixed Acc | 边际 Acc 变化 |
|---|---|---|---|---|---|
| baseline_raw | 0.8699 | 0.375 | 0.071 | 0.625 | 基线 |
| crop_only | **0.9024** | 0.458 | **0.010** | 0.542 | **+0.033** |
| crop_slither | 0.8212 | 0.375 | 0.131 | 0.625 | -0.081 |
| crop_slither_cot | 0.8049 | 0.375 | 0.152 | 0.625 | -0.016 |
| crop_slither_multi | 0.8049 | 0.542 | 0.111 | 0.458 | 0.000 |

> DeepSeek-chat, T=0, repeat=3 均值, 41 样本。

**实验结果解读**：

- **crop_only 边际增益最大（+0.033）**：代码裁剪是消融实验中唯一正向贡献的模块。消除无关代码使模型注意力集中于风险点，漏报率压至 0.010。**但代价显著**：裁剪同时剥离了 ReentrancyGuard 安全上下文，FPR 从 0.375 升至 0.458——fixed 变体识别率仅 0.542。这一矛盾直接驱动了后续的 Guard 注入实验。
- **crop_slither 退化（-0.081）**：加入 Slither 静态分析摘要后 Acc 反而从 0.902 降至 0.821，FNR 升至 0.131。**裸 Slither 报告是噪声而非信号**——Slither 输出的结构化文本（外部调用列表、状态变量读写清单）以密集格式注入 Prompt，稀释了模型对代码本身的注意力。
- **crop_slither_cot 和 crop_slither_multi 进一步退化**：CoT 推理和多合约上下文同样未能逆转 Slither 带来的负面影响。

**核心发现**：Slither 裸报告反而不如裁剪后代码本身有效。**但 Slither 的信息可以转化为信号**——在 4.4 节中，当 Slither 报告与 bypass 检测标签和 Prompt 规则组合使用时，Acc 跃升至 0.935（全实验最高）。这验证了一个关键原则：**静态分析工具的输出需要上下文引导才能成为有效证据；直接裸喂给 LLM 就是噪声。** 此外，裁剪仍是唯一有效的独立优化手段。**这直接驱动了 slice_v1 切片引擎的设计。**

---

### 4.2 切片优化（reentrancy_slice_v1）：精准裁剪 + 全局视角

**驱动问题**：消融实验表明现有裁剪逻辑存在两个缺陷——缺乏全局视角（无法区分"重要合约"与"模板合约"）和丢失安全上下文。如何设计更精准的代码裁剪？

**实验设计**：开发 reentrancy_slice_v1 切片引擎，引入 4 项基于全局统计的优化规则：外部调用精确化（排除 ERC20）、函数级筛选（LOC ≥ 5）、显著函数 Top 10%（全局唯一名 + 长度阈值）、贪心填充 3800 字符（p99 上限）。同时注入 Guard 源码（`_inject_reentrancy_guard`），当检测到合约使用 nonReentrant 修饰符时，自动将父合约 ReentrancyGuard 源码嵌入切片。

**切片效果**：原始 91,438 → 43,830 字符（压缩率 47.9%），48/49 样本控制在 3800 字符以内。

| 方案 | Accuracy | FPR | FNR | fixed Acc | 说明 |
|---|---|---|---|---|---|
| crop_only（消融最优） | 0.9024 | 0.458 | 0.010 | 0.542 | 基准 |
| slice_v1 + Guard | 0.8861 | 0.375 | 0.051 | 0.625 | 切片 v1 + Guard |

> Guard = 原始 Prompt 模板（不含 nonReentrant 规则）+ 切片 v1 + 守卫源码注入。

**结果解读**：Guard 注入后 Acc 为 0.886，模型看到 nonReentrant 修饰符但 Slither 的结构化报告稀释了对代码本身的注意力。按场景拆解后暴露了严重的不均衡问题：

**slice_v1 + Guard 分场景 fixed 变体识别率**（3 次重复累计）：

| 场景 | 总判定次数 | TP | TN | FP | FN | 整体 Acc | fixed Acc |
|---|---|---|---|---|---|---|---|
| standard_reentrancy | 72 | 65 | 6 | 0 | 1 | 0.986 | 1.000 |
| cross_function | 18 | 10 | 6 | 0 | 2 | 0.889 | 1.000 |
| **reentrancy_via_modifier** | 15 | 9 | 3 | **3** | 0 | 0.800 | **0.500** |
| **cross_contract** | 18 | 12 | 0 | **6** | 0 | 0.667 | **0.000** |

> 各场景含 2 个 fixed 样本 × 3 次重复 = 6 次判定。fixed Acc = TN/(TN+FP)。

**标准重入和跨函数重入的 fixed 变体完美识别**（Acc=1.000），说明 Guard 注入对简单场景有效。**但 modifier 重入的 fixed 有 50% 误报，跨合约重入的 fixed 更是 100%（6/6）全误报**——模型"看到"了 nonReentrant 源码却不理解其语义，在 modifier 执行顺序混淆和跨合约复杂调用链下仍仅凭 `call{value:...}` 模式判定漏洞。**这驱动了 Prompt 规则注入实验。**

---

### 4.3 Prompt 规则注入：从"看到"到"理解"

**驱动问题**：Guard 注入后 FPR 仍 0.375——模型看到了 nonReentrant 修饰符但不理解它意味着安全。能否通过系统 Prompt 规则教会模型 nonReentrant 的语义？

**实验设计**：在所有 5 个 Prompt 模板中注入显式规则——`nonReentrant` 修饰符 = 重入保护锁 → 不应判定为漏洞。同时设置对照组：在代码注释中添加同样内容（解释性注释），验证"指令通道"与"内容通道"的差异。

| 方案 | Accuracy | FPR | FNR | fixed Acc |
|---|---|---|---|---|
| Guard（基线） | 0.8861 | 0.375 | 0.051 | 0.625 |
| + Prompt 规则 | 0.8943 | 0.375 | 0.040 | 0.625 |
| + Prompt 规则 + bypass | **0.9349** | **0.250** | **0.020** | **0.750** |

**结果解读**：

- **Prompt 规则单独使用无法降低 FPR**：FPR 与 Guard 基线持平（0.375）。在 Slither 提供的静态分析上下文中，纯文本规则无法独立修复固定变体的误判。
- **Prompt 规则 + bypass 才是真正的增益组合**：同时使用规则和绕过检测时，Acc 跃升至 0.935，FPR 降至 0.250，FNR 压至近乎零的 0.020——**Slither 报告 + bypass 标签 + Prompt 规则的组合效应远超单独使用任一项**。
- **解释性注释结论不变**：模型将代码注释视为可忽略文档。

---

### 4.4 切片级绕过检测：代码证据驱动的差异化判断

**驱动问题**：Prompt 规则矫枉过正，导致 FNR 从 0.030 升至 0.101。根源在于纯文本规则无法让模型区分"nonReentrant 保护充分"和"nonReentrant 存在绕过路径"两种情况。如何让模型基于代码结构做差异判断，而不是依赖黑名单式的规则？

**实验设计**：在切片引擎中新增 `_generate_security_summary` 模块，分析每个样本中 nonReentrant 锁的覆盖范围：(a) 统计加锁/未加锁函数比例；(b) 识别可被攻击者绕过的未保护调用路径；(c) 检测跨合约调用模式。生成结构化标签——`[SAFE]`（所有风险函数已覆盖）或 `[BYPASS-RISK]`（存在绕过路径）——直接注入切片上下文。

| 方案 | Accuracy | FPR | FNR | fixed Acc |
|---|---|---|---|---|
| Guard + Prompt 规则（无 bypass） | 0.8943 | 0.375 | 0.040 | 0.625 |
| Guard + Prompt 规则 + bypass | **0.9349** | **0.250** | **0.020** | **0.750** |

**结果解读**：

- Guard + Prompt 规则组合仅实现 Acc 0.894，FPR 仍为 0.375——纯文本规则无法独立降低误报率。
- 叠加 bypass 检测后，Acc 升至 0.935，FPR 降至 0.250，FNR 降至 0.020，fixed Acc 达 0.750。

---

### 4.5 分场景分析

| 场景 | 消融最优 | Guard | 最终 (bypass+Prompt) | 说明 |
|---|---|---|---|---|
| standard_reentrancy | 0.972 | 0.986 | 0.931 | 经典模式几乎完美 |
| cross_function | 0.833 | 0.889 | 1.000 | 最终方案 zero FP |
| reentrancy_via_modifier | 0.800 | 0.800 | 0.800 | modifier 执行顺序混淆，FP 顽固 |
| cross_contract | 0.722 | 0.667 | 0.556 | crosschain 模式偏离典型重入 |

**fixed 变体误判演变**（4 类场景累计）：Guard 注入阶段 9 FP/24 → Prompt 规则 6 FP/24（↓33%）→ 最终方案 6 FP/24（已触底板）。顽固 FP 始终来自 modifier_fixed（modifier 执行顺序不被理解）和 crosschain_fixed（跨链 Bridge 调用不匹配重入模板）。

### 4.6 数据集清洗效果验证

| 指标 | 旧（37正:4负） | 新（33正:8负） |
|---|---|---|
| smartbugs 近重复 | 8 个 | **0** |
| sample_id 碰撞 | 8 组 | **0** |
| baseline_raw Acc | 0.935（虚高） | **0.870（真实）** |
| FPR 评估稳定性 | 差（分母 4） | **中（分母 8）** |

旧数据集 Acc 虚高 6.5 个百分点，验证了清洗的必要性。crosschain 样本的跨合约 Acc 仅 0.556–0.667，其漏洞模式与典型重入存在本质差异，未来应考虑独立评估。

---

### 4.7 RAG + 强约束 Prompt：借鉴 PropertyGPT 的检索增强重入检测

**驱动问题**：前四轮实验在 zero-shot 条件下进行，模型从未见过重入漏洞的参考示例。PropertyGPT 的 RAG + In-Context Learning 方案能否通过检索相似的已知重入模式，在 Few-Shot 条件下提升判断准确性？

**方法迁移**：将 PropertyGPT 的范式适配到重入检测——属性向量数据库 → 重入模式向量库（8 条，覆盖 4 类 × vuln/safe）；代码嵌入检索 → TF-IDF n-gram 嵌入 + 余弦相似度检索。

引入 PropertyGPT 的 MUST/MUST NOT/REMEMBER 约束层级。与之前 Prompt 规则的区别：描述性规则告知"这是什么意思"，指令性规则告知"你必须怎么做"。

```
- MUST: nonReentrant/noReentrant 修饰符保护 → 判定 safe
- MUST NOT: 不能仅因 call{value:...}/transfer/send 判定漏洞
- REMEMBER: [SAFE] 标签是强信号
```

**实验结果**：

| Profile | Accuracy | FPR | FNR | fixed Acc | ΔAcc (vs baseline) |
|---|---|---|---|---|---|
| baseline_raw | 0.9355 | 0.250 | 0.037 | 0.750 | 基线 |
| crop_slither | 0.9140 | 0.167 | 0.074 | 0.833 | -0.022 |
| **rag_strong**  | **0.9032** | **0.000** | **0.111** | **1.000** | **-0.032** |
| rag_fewshot | 0.8387 | **0.000** | 0.185 | **1.000** | -0.097 |

> DeepSeek-chat, T=0, repeat=3 均值, 41 样本, reentrancy_slice_v1 切片。

**分场景拆解**：

| 场景 | baseline_raw | crop_slither | rag_strong | rag_fewshot |
|---|---|---|---|---|
| standard_reentrancy | 1.000 | 0.970 | **1.000** | 0.909 |
| cross_function | 0.778 | 0.889 | **1.000** | **1.000** |
| cross_contract | 0.889 | 0.778 | 0.667 | 0.667 |
| **reentrancy_via_modifier** | **0.667** | **0.667** | **0.333** | **0.333** |

**实验结果解读**：

**1. FPR=0。** 所有 RAG profile 的 FPR 降至 0.000——实验中首次实现零误报。rag_strong 的 fixed Acc=1.000（24/24 正确），此前最优仅 0.750。

**2. rag_strong 的 trade-off。** FPR=0 的同时 FNR=0.111，Acc=0.903。用 3.2 pp 的 Acc 换取了 25 pp 的 FPR 改善。零误报在审计场景中具有实用价值——消除了对安全合约的错误标记。

**3. Few-Shot 增加保守性。** rag_fewshot 的 FNR 从 0.111 升至 0.185（+67%）。对于经典 withdraw 模式，检索到的 top-4 示例中 3 个为 safe、1 个为 vuln（3:1），模型倾向于安全判断。这与 PropertyGPT 的预期相反：生成任务中 Few-Shot 提供模板有效，判别任务中可能引入分布偏差。

**4. modifier 是强约束的代价。** rag_strong 的 modifier Acc 从 0.667 降至 0.333——MUST 约束使模型将 modifier 中的任意保护字样（如 `neverReceiveAirdrop`）均视为安全信号。PropertyGPT 处理的是生成任务，本文处理的是判别任务，两者的任务特性差异导致 RAG 效果不可直接迁移。

**与原始 bypass+Prompt 方案的交叉对比**：

| 指标 | bypass+Prompt (原始最优) | rag_strong (本次最优) | 差异 |
|---|---|---|---|
| Accuracy | **0.935** | 0.903 | -0.032 |
| FPR | 0.250 | **0.000** | **-0.250** |
| FNR | **0.020** | 0.111 | +0.091 |
| fixed Acc | 0.750 | **1.000** | **+0.250** |
| modifier Acc | **0.800** | 0.333 | -0.467 |

两种方案代表了不同的优化方向：bypass+Prompt 追求 FNR 最低（漏报最少），牺牲一定的 FPR；rag_strong 追求 FPR 最低（误报最少），牺牲一定的 FNR。在安全审计的完整工作流中，两者可以互补——rag_strong 作为第一道"零误报过滤"，将确定安全的合约直接放行；bypass+Prompt 作为第二道"深度检测"，对剩余样本进行更细致的判定。

**迭代修订与多维排序的消融验证**：

为进一步验证 RAG 各模块的独立贡献，我们追加了一组对照实验，在 rag_fewshot 基础上叠加迭代修订（借鉴 PropertyGPT 的编译反馈循环）和多维排序（借鉴 PropertyGPT 的四维加权评分）。结果如下：

| Profile | Accuracy | FPR | FNR | 说明 |
|---|---|---|---|---|
| rag_strong (纯 RAG) | **0.9032** | 0.000 | **0.111** | 最优 |
| rag_fewshot | 0.8387 | 0.000 | 0.185 | +Few-Shot |
| rag_fewshot_revision | 0.8172 | 0.000 | **0.210** | +迭代修订 |
| rag_full | 0.8387 | 0.000 | 0.185 | +多维排序 |

迭代修订和多维排序均未带来正向增益。迭代修订的退化尤为显著——模型在修订轮次中变得更加保守，FNR 持续攀升。这一发现与 PropertyGPT 的经验形成对比：PropertyGPT 中编译反馈迭代修订之所以有效，是因为编译错误的信号明确（"变量未定义""语法错误"——确定性修正目标）；而重入检测中 JSON 格式修正和置信度反馈无法提供等价的"硬信号"，修订反而强化了模型的初始保守倾向。

---

### 4.8 合约标准增强：Entry-Reentry-Flow 三步判定

**驱动问题**：rag_strong 的 FPR=0 代价是 modifier Acc=0.333——所有 modifier insecure 样本漏报。Cai et al. (2025) 指出合约标准（ERC20/721/777/1155）定义了钩子触发语义，可以作为先验知识注入检测流程。能否通过标准语义增强，让模型理解 modifier 的执行顺序和 hook 机制？

**方法设计**：

借鉴 Cai et al. 的三组件框架（Entry Point → Reentry Point → State Flow），将其转化为 LLM Prompt 的结构化分析步骤。构建 ERC 标准知识库（`src/standards_kb.py`），在预处理阶段检测合约标准类型，将标准语义注入静态分析摘要。

Prompt 含三个要素：

| 要素 | 内容 | 作用 |
|---|---|---|
| Entry-Reentry-Flow 框架 | 步骤1: 识别可劫持调用 → 步骤2: 识别可利用操作 → 步骤3: 追踪状态流 | 结构化分析 |
| ERC 标准知识 | ERC777.transfer → tokensToSend hook；ERC721.safeTransferFrom → onERC721Received hook | 语义感知 |
| Modifier 执行顺序 | `_;` 之前上锁才有效；`_;` 之后更新状态则创建重入窗口 | 填补模型盲区 |

关键规则在 Prompt 首尾以不同表述重复（Verbose Elaboration）。

**预处理增强**：扩展 `_build_static_summary`，调用 `detect_contract_standard()` 检测标准类型，对外部调用标注 `[HIJACKABLE]`。示例：

```
增强前: 外部调用=TUPLE_0(bool,bytes)=LOW_LEVEL_CALL
增强后: [STANDARD] 检测到 ERC777
        外部调用=token.transferFrom() [HIJACKABLE: 触发 tokensToSend hook]
```

**实验设计**：在 §4.7 最优方案（rag_strong）和消融基线（crop_slither）基础上，新增 `standards_entry` profile，使用 `reentrancy_slice_v1` 切片 + 增强摘要 + 三步判定 Prompt。DeepSeek-chat、T=0、repeat=3。

**实验结果**：

| Profile | Accuracy | FPR | FNR | fixed Acc | modifier Acc |
|---|---|---|---|---|---|
| crop_slither | 0.946 | 0.250 | 0.025 | 0.750 | 1.000 |
| rag_strong | 0.936 | 0.000 | 0.074 | 1.000 | 0.667 |
| standards_entry | 0.914 | 0.250 | 0.062 | 0.750 | **1.000** |

**分场景**：

| 场景 | rag_strong | standards_entry |
|---|---|---|
| standard_reentrancy | 1.000 | 1.000 |
| cross_function | 1.000 | 1.000 |
| reentrancy_via_modifier | 0.667 | **1.000** |
| cross_contract | 0.667 | 0.333 |

**结果解读**：

**modifier Acc 首次 1.000。** 此前所有方案的 modifier Acc 均不超过 0.800。三步判定框架中的 modifier 执行顺序分析——区分 `_;` 之前上锁（有效保护）与 `_;` 之后更新状态（重入窗口）——是突破关键。例如 `InsecureAirdrop.sol`：`canReceiveAirdrop` modifier 中 `receivedAirdrop[msg.sender] = true` 在 `_;` 之后执行，rag_strong 看到 `neverReceiveAirdrop` 字样即判 safe（confidence=0.0，FN）；standards_entry 正确识别了 `_;` 之后的延迟状态更新构成重入窗口（TP）。

**cross_contract FPR=1.000。** 标准知识使模型将"存在 hijackable 调用"等同于"存在漏洞"。Safe 版跨合约样本虽使用 ERC777.transferFrom，但通过 CEI 原则避免了重入——模型未能区分"调用可劫持"与"调用已被保护"。

**两种方案错误模式正交。** rag_strong 的 FN（modifier insecure）是 standards_entry 的 TP；standards_entry 的 FP（cross_contract fixed）是 rag_strong 的 TN。这驱动了 §4.9 的组合设计。

---

### 4.9 confidence-gated 组合流水线

**驱动问题**：rag_strong 的 FPR=0 代价是 modifier FNR=1.0；standards_entry 的 modifier Acc=1.0 代价是 cross_contract FPR=1.0。两者错误正交——rag_strong 的 FN 是 standards_entry 的 TP，standards_entry 的 FP 是 rag_strong 的 TN。直接合并两套 Prompt 已验证不可行（信号冲突，Acc≈0.936）。能否设计一种保持各组件独立性的组合方案？

**核心洞察——confidence 作为切换信号**：

rag_strong 正确预测时 confidence >0.9，FN 时 confidence=0.0。模型用置信度表达了"我不知道"。这提供了天然切换信号：当 rag_strong confidence < 0.5，切换到 standards_entry。

**设计**：

```
Pass 1: rag_strong → prediction + confidence
  ├─ confidence ≥ 0.5 → 采纳 Pass 1
  └─ confidence < 0.5 → Pass 2: standards_entry → 采纳 Pass 2
```

设计特点：切换信号来自 rag_strong 自身的 confidence（非外部规则）；每轮仅约 1 个样本触发 Pass 2（2.4% 额外开销）；FPR 安全——confidence<0.5 从未在 safe 样本上出现。

**实验设计**：实现 `two_pass` profile，对比 crop_slither、rag_strong、standards_entry。DeepSeek-chat、T=0、repeat=3。

**实验结果**：

| Profile | Accuracy | FPR | FNR | fixed Acc | modifier Acc |
|---|---|---|---|---|---|
| crop_slither | 0.946 | 0.250 | 0.025 | 0.750 | 1.000 |
| rag_strong | 0.936 | 0.000 | 0.074 | 1.000 | 0.667 |
| standards_entry | 0.914 | 0.250 | 0.062 | 0.750 | 1.000 |
| two_pass | **0.957** | **0.000** | **0.049** | **1.000** | **0.889** |

**Pass 2 触发统计**（3 轮累计）：

| 指标 | 数值 |
|---|---|
| 总预测 | 123 |
| Pass 2 触发 | 3（每轮 1 次） |
| Pass 2 成功修正 | 2/3 |
| 误触发（safe 样本） | 0 |
| 额外开销 | 2.4% |

**结果解读**：

Acc=0.957，此前 FPR=0 的最高 Acc 为 rag_strong 的 0.904，提升了 5.3 pp。modifier Acc 从 0.667 升至 0.889：modifier insecure 共 6 次判定，two_pass 正确检测 5 次（rag_strong 为 0/6）。FPR 保持 0.000：fixed 合约 12 次判定全部正确。未解决的误差：`05_cross_contract_insecure`（3/3 FN，rag_strong 和 standards_entry 均以 confidence=1.0 判错，无法通过 confidence 切换修正）；`03_modifier_insecure`（1/3 FN，1 次 Pass 2 未修正）。

**与各方案对比**：

| 方案 | Acc | FPR | FNR | fixed Acc | modifier Acc |
|---|---|---|---|---|---|
| bypass+Prompt | 0.935 | 0.250 | 0.020 | 0.750 | 0.800 |
| rag_strong | 0.904 | 0.000 | 0.111 | 1.000 | 0.333 |
| standards_entry | 0.914 | 0.250 | 0.062 | 0.750 | 1.000 |
| two_pass | **0.957** | **0.000** | **0.049** | **1.000** | **0.889** |

**设计启示**：直接合并两套 Prompt 导致信号冲突（Acc≈0.936，等于 rag_strong）。two_pass 的成功表明：当两个策略的推理逻辑冲突时，保持组件独立性（架构层面的编排）优于 Prompt 层面的融合。

---

## 讨论

### 5.1 各优化手段的增益与代价量化

下表按实验时间顺序汇总每项优化手段相对于其前驱方案的边际变化，揭示每一步的净收益与代价。

| 优化手段 | 驱动源 | ΔAcc | ΔFPR | ΔFNR | 净收益 | 代价 |
|---|---|---|---|---|---|---|
| 代码裁剪（crop_only） | 消融发现 | **+0.033** | +0.083 | -0.061 | Acc 大幅提升，FNR 降至近乎零 | FPR 飙升（安全上下文丢失） |
| Slither 摘要 | crop_only | -0.081 | -0.083 | +0.121 | 裸报告是噪声 | 需配合 bypass 使用 |
| CoT 推理 | 消融叠加 | -0.041 | -0.083 | +0.071 | 无 | Acc 进一步退化 |
| 多合约上下文 | 消融叠加 | 0 | +0.167 | -0.041 | 无 | FPR 全指标最差 |
| Guard 注入 | crop_only | -0.016 | -0.083 | +0.041 | FPR 下降，FNR 上升 | 安全上下文部分恢复 |
| Prompt 规则 | Guard | +0.008 | 0 | -0.011 | 单独使用无法降低 FPR | 需配合 bypass |
| bypass + Prompt + Guard + Slither | Guard | **+0.049** | **-0.125** | **-0.031** | Acc 0.935 | 无 |
| RAG 强约束 (rag_strong) | bypass+Prompt | -0.032 | **-0.250** | +0.091 | FPR=0，fixed Acc=1.0 | FNR 上升，modifier 全漏 |
| RAG Few-Shot (rag_fewshot) | rag_strong | -0.065 | 0 | +0.074 | 无 | Few-Shot 增加保守性 |
| RAG 迭代修订 | rag_fewshot | -0.022 | 0 | +0.025 | 无 | 修订强化保守倾向 |
| 标准增强 (standards_entry) | rag_strong | -0.021 | +0.250 | -0.012 | modifier Acc=1.0 | cross_contract FPR=1.0 |
| confidence-gated 组合 (two_pass) | rag_strong | **+0.022** | 0 | **-0.025** | Acc=0.957，FPR=0 | +2.4% API |

**设计启示**：Slither 裸报告是噪声，配合 bypass 检测后转化为有效信号。RAG 强约束实现了 FPR=0。标准增强攻克了 modifier 盲区。two_pass 通过 confidence-gated 组件协作，以 2.4% 额外 API 开销同时继承了 rag_strong 的 FPR=0 和 standards_entry 的 modifier 检测能力。

### 5.2 核心机制发现

**发现一：指令通道 ≠ 内容通道。** 系统 Prompt 中的规则被模型视为需遵循的权威约束（指令通道），而代码内嵌注释仅被视为可忽略的上下文文档（内容通道）。这一发现的理论意义在于：当 LLM 缺乏领域语义理解时，*告知规则*远比*在数据中展示规则*有效。

**发现二：证据优于规则。** Prompt 规则虽然降低了 FPR，但带来了不可控的过度泛化（FNR 飙升）。将安全证据直接嵌入切片上下文（`[SAFE]`/`[BYPASS-RISK]` 标签）使模型能做基于具体代码结构的差异化判断，在不依赖 CoT 的前提下实现 FNR 回落。*代码结构中的具体标记比系统级规则更精细。*

**发现三：裁剪的注意力机制效应。** 代码裁剪在所有有效方案中均贡献最大边际增益。这从实证角度支持了一个直观假设：LLM 的注意力容量有限，无关上下文的存在会稀释模型对关键风险信号的敏感度。*"少即是多"在安全检测任务中成立。*

**发现四：约束层级决定行为边界。** MUST/MUST NOT 强约束（源自 PropertyGPT 的提示词设计哲学）将 FPR 从 0.250 压至 0.000，而之前的"描述性规则"（"nonReentrant = safe"）仅降至 0.375。两种约束形式的效果差异揭示了 LLM 对指令的层级敏感度：*"你必须做 X"（指令性）远比"X 意味着 Y"（描述性）有效。* 这一发现将"指令通道 ≠ 内容通道"（发现一）从代码注释 vs Prompt 规则的对比，进一步细化为 Prompt 内部约束强度的对比。

**发现五：Few-Shot 在判别任务中的双刃剑效应。** PropertyGPT 中 Few-Shot 示例提升了属性生成的准确性，但在本实验的重入检测判别任务中，Few-Shot 示例反而显著增加了保守性（FNR ↑67%）。根因在于：生成任务中示例提供的是"结构模板"，而判别任务中示例提供的"答案参考"可能引入分布偏差——检索到的 safe 示例过多时，模型倾向于安全判断。*RAG 在生成任务与判别任务中的效果不可直接迁移。*

**发现六：外部信号硬度决定反馈有效性。** PropertyGPT 的编译错误反馈是"硬信号"（确定性：代码能否编译），因此迭代修订有效；而重入检测中的 JSON 格式修正和置信度反馈是"软信号"（不确定性：模型自己也不确定），迭代修订反而强化初始偏见。*反馈信号的确定性是迭代修订成功的必要条件。*

**发现七：语义感知在子任务间收益不对称。** ERC 标准知识注入使模型从模式匹配（"看到 call{value:...}"）提升为因果推理（"ERC777.transfer 触发 tokensToSend hook"）。该增强在 modifier 场景中有效（Acc 0.333 → 1.000），但在 cross_contract 中引起过度泛化（FPR 0 → 1.0）。域知识的注入收益与代价在子任务粒度上不对称，需要子任务级别的校准。

**发现八：confidence 反映模型的知识边界自我感知。** rag_strong 正确预测时 confidence >0.9，FN 时 confidence=0.0。这表明 confidence 不仅反映预测可靠性，更反映了模型对自身知识边界的自我感知。该发现将 confidence 从预测质量度量提升为架构切换信号，驱动了 two_pass 的设计。

**发现九：组件编排优于 Prompt 融合。** 直接合并两套 Prompt 导致信号冲突（Acc≈0.936），而保持独立性的 two_pass 实现了超越任一组件的结果（Acc=0.957）。当多个 LLM 策略的推理逻辑冲突时，架构层面的组件编排优于 Prompt 层面的逻辑混合。

### 5.3 设计方法论反思

**先清洗数据，再开始实验。** 旧数据集 0.935 的虚高准确率若被直接采纳，将使后续所有结论失去统计基础。数据质量检查应作为实验流程的第零阶段。

**消融实验需"单向变量"原则。** 5 个 profile 的递进叠加设计使每一步的边际贡献可精确归因。若一次性叠加所有模块，即使最终指标优异，也无法区分哪个模块贡献了真正的增益。

**模型能力上限不可忽视。** 迭代优化中累积的证据表明 DeepSeek-chat 对 Solidity modifier 执行语义存在明确理解天花板。当指标出现平台期时，继续在相同模型上做 Prompt 层面的微调可能收效甚微——此时应考虑切换更强的模型或引入互补的确定性分析工具。

**crosschain 样本的生态位问题。** 跨链合约的漏洞模式（Bridge 调用）与典型资金重入存在本质差异，在标准 benchmark 中持续拉低跨合约场景 Acc。将其独立为子任务评估比强行纳入统一基准更合理。

### 5.4 局限性

- **类别不平衡**：33 正 : 8 负，FPR 分母仅 8，统计效力有限。
- **模型能力天花板**：DeepSeek-chat 无法完全理解 modifier 的执行语义（`_` 占位符），modifier 类重入的 FP 始终顽固。
- **数据泄漏风险**：smartbugs 合约均来自 Etherscan 已验证主网合约，LLM 预训练语料可能包含。
- **规模有限**：41 样本适合消融分析，距离大规模 benchmark 仍有差距。
- **zero-shot 设置**：未进行微调或 few-shot，当前结论仅适用于零样本条件。

### 5.5 未来工作

- **更强模型验证**：在 GPT-4o 或 DeepSeek-v4 系列上复现核心实验链路，探测 modifier 语义理解的上限。
- **链上合约验证**：将 The DAO、Lendf.Me 等真实主网受害合约纳入流水线，检验方法的真实泛化能力。
- **Self-consistency 机制**：对低置信度预测采用多次采样加固，在不改变模型本身的前提下提升判定稳定性。
- **数据集扩展**：当前仅 8 个 paired fixed/insecure 样本，扩充此类对照样本将显著提升 FPR/FNR 的统计效力。
- **RAG 探索 ✅**：检索增强生成方案已在本研究第 5 轮实验中实现（见 §4.7），验证了强约束 Prompt + Few-Shot 示例的组合效果。FPR 归零的成果证明了 RAG 思路的价值，但也暴露了 Few-Shot 在判别任务中的双刃剑效应。未来方向：(a) 优化检索的正负样本平衡策略，(b) 引入 SWC Registry、CVE 记录等更大规模的外部知识源，(c) 探索针对 modifier 重入场景的专用 Few-Shot 示例设计。

### 5.6 相关工作分析与借鉴：Gas-Wasting Code Smells 论文的启示

Jiang et al. (2024) 在 *IEEE TSE* 上发表的"Unearthing Gas-Wasting Code Smells in Smart Contracts with Large Language Models"提出了一个系统化的 LLM 驱动智能合约代码气味检测流水线。虽然其任务目标（Gas 浪费检测）与本研究的重入漏洞检测不同，但其 **Prompt 框架设计方法论** 和 **迭代发现流程** 对本研究具有直接的借鉴价值。

**Gas-Wasting 论文的核心设计——四模块 Prompt 框架**：

该论文将 Prompt 设计从单一文本提升为**复合结构**，由四个具有独立设计动机的模块组成：

| 模块 | 设计动机 | 内容 |
|---|---|---|
| **Block 1: Introduction & Problem Formulation** | CoT + Verbose Elaboration | 注入领域知识、两步解释关键概念（开头一次 + 结尾用不同视角重复一次） |
| **Block 2: Few-Shot Example Block** | 示例引导 | 精选的 Gas 浪费代码气味及解释 |
| **Block 3: Input Codes Block** | 代码输入 | 函数级贪心采样的合约代码 |
| **Block 4: Self-Inspection Block** | 自我反思 | 三步：(a) 可读性/可维护性/安全性 tradeoff 评分；(b) 下次如何改进；(c) Prompt 中是否有歧义 |

**四个设计动机**：

1. **Few-Shot Examples (FSE)**：提供精选示例引导任务完成，资源高效（无需微调）
2. **Chain of Thought (CoT)**：分步推理引出更结构化的输出，但作者也警示了 CoT 的忠实性问题——解释未必反映真实推理过程
3. **Verbose Elaboration**：从不同视角重复解释关键概念，大幅降低 LLM 误解 Prompt 意图的风险
4. **Self-Inspection**：作为 CoT 的增强形式，要求 LLM 从多个维度反思自己的输出质量和推理过程

**8 轮迭代发现流程**：每轮采样 10 个合约，人工验证 LLM 报告的结果，将验证通过的新发现纳入分类体系，再进入下一轮——形成"发现→验证→分类→反馈"的闭环。

**与本研究的交叉映射**：

| Gas-Wasting 论文设计 | 本研究现状 | 可借鉴方向 |
|---|---|---|
| **Self-Inspection Block** | CoT 模板有步骤 7（自我审查），但较简单：仅 3 个问题 | 扩展为 tradeoff 评分 + 改进建议 + Prompt 歧义检测的三维反思 |
| **Verbose Elaboration** | 有 nonReentrant 规则区块，但仅描述一次 | 在 Prompt 开头和结尾用不同表述重复关键判定规则，降低 LLM 的误解概率 |
| **Few-Shot Example Block** | RAG 动态检索示例 | 增加人工精选的"锚定示例"——经过验证的高质量正负对照，作为 RAG 检索的补充基准 |
| **迭代轮次 + 人工验证** | repeat=3 仅做统计重复，无人工验证环节 | 引入人工复核机制：对高不一致样本（3 次预测结果不统一）进行人工判定，反馈结果用于改进 Prompt |
| **8 轮渐进发现** | 单轮全量实验 | 分轮次实验，每轮聚焦前一轮的失败案例，形成针对性改进循环 |
| **Entropy 多样性度量** | 仅报告 Accuracy/FPR/FNR | 增加模型输出的多样性分析，评估是否存在系统性的类别偏向 |

**当前研究可直接采纳的两项低成本改进**：

**改进一：Verbose Elaboration 的双视角规则注入。** 当前 Prompt 模板中的 nonReentrant 规则区块仅在开头出现一次。借鉴 Gas-Wasting 论文的 Verbose Elaboration 策略，可以在 Prompt 末尾以"重要提醒"的形式，用不同的表述再次强调关键判定规则。例如：

```
开头（描述性）：nonReentrant 工作原理：执行函数体前 locked=true 上锁，require(!locked) 阻止重入
结尾（指令性）：再次提醒：看到 nonReentrant/noReentrant → 合约已受重入锁保护 → 必须判定为 safe
```

这与我们在 §5.2 中发现的"指令通道 ≠ 内容通道"规律高度契合——Verbose Elaboration 本质上是用双重通道传递同一信息，增加指令被模型遵循的概率。

**改进二：增强 Self-Inspection。** 当前 CoT 模板的步骤 7 仅有 3 个审查问题。借鉴 Gas-Wasting 论文的三维反思，可扩展为：

```
(a) 对本次判断给出 confidence breakdown：代码证据充分度 / 语义理解确定度 / 外部依赖可靠性
(b) 如果这次判断有误，最可能的原因是什么？
(c) Prompt 中是否有表述不清的地方？如果有，请指出
```

问题 (c) 尤其重要——它不仅帮助模型反思，还为 Prompt 模板的迭代优化提供了来自模型视角的直接反馈信号。

**不推荐直接迁移的设计**：

- **人工验证重度依赖**：Gas-Wasting 论文依赖两名独立审查者进行人工验证（19.32% 初始分歧率），这在重入检测的大规模部署中不可持续。bypass 标签的自动检测机制（§4.4）已在本研究中证明是更可扩展的替代方案。
- **8 轮分轮实验**：Gas-Wasting 论文需要人工介入每轮的结果筛选。本研究的 `repeat=3` 统计重复已通过均值 ± 标准差提供了足够的统计稳定性，分轮实验的额外复杂度在当前规模下收益有限。

**总结**：Gas-Wasting 论文对本文的主要启示是 Prompt 设计的模块化思维——将 Prompt 视为由独立设计动机驱动的可组合结构，而非整体文本。Verbose Elaboration 和改进 Self-Inspection 已在 §4.8 和 §4.9 的 Prompt 设计中得到应用。

### 5.7 相关工作分析与借鉴：基于合约标准的静态污点分析重入检测

Cai et al. (2025) 在 *IEEE TIFS* 上发表的"Detecting Reentrancy Vulnerabilities for Solidity Smart Contracts With Contract Standards-Based Rules"提出了基于合约标准的静态分析框架。其将合约标准作为先验知识注入检测流程的思想，为本研究的 LLM 方法提供了上下文增强方向——尤其是解决 modifier 和跨合约重入的漏报问题。

**论文核心思路——三组件框架**：

该论文将重入漏洞检测重新形式化为三个子任务：

| 组件 | 功能 | 关键技术 |
|---|---|---|
| **Entry Point Identification** | 识别包含"可劫持外部调用"的函数 | 利用 ERC 标准知识库（Table I）判断外部调用是否能触发攻击者 hook |
| **Reentry Point Identification** | 识别包含"可利用操作"的函数 | 利用标准定义的 transfer 方法（Table II）识别直接/间接可利用操作 |
| **State Variable Flow Tracking** | 追踪延迟更新的状态变量流向 | 静态污点分析：taint source（延迟更新变量）→ taint sink（可利用操作） |

**标准知识驱动的切入点识别（Table I）**：

该论文的核心洞察是：当前区块链生态中大多数智能合约遵循技术标准（ERC20/721/777/1155），这些标准明确定义了哪些函数会触发回调 hook。例如：

| 标准 | 可劫持的外部调用 | 回调机制 |
|---|---|---|
| ERC20 | `transfer()`, `transferFrom()` | 标准 transfer 不触发 hook，但特定实现可重写 |
| ERC721 | `safeTransferFrom()` | 触发 `onERC721Received` hook |
| ERC777 | `transfer()`, `transferFrom()`, `burn()` | 触发 `tokensToSend` / `tokensReceived` hook |
| ERC1155 | `safeTransferFrom()`, `safeBatchTransferFrom()` | 触发 `onERC1155Received` hook |

通过识别外部调用对象的类型（如 `Token` 的类型为 `ERC777`），可以**在不确定被调用方具体实现的情况下**，仅凭标准语义推断该调用是否可劫持。

**可利用操作的二层分类（Table II）**：

- **Direct exploitable**：直接将加密货币转移给攻击者（如 `.call{value:}()`, `.transfer()`, `ERC20.transfer()`）。通过数据依赖分析判断 transfer 目标是否为 `msg.sender`。
- **Indirect exploitable**：操纵直接可利用操作所依赖的状态变量（如 `delete Exist[msg.sender]` 允许绕过条件检查，间接实现重复取款）。

**污点分析桥接 entry/reentry point**：

将 entry point 中延迟更新的状态变量标记为 taint source，追踪其在 reentry point 中的控制流和数据流传播。如果污点能传播到可利用操作，则确认存在重入漏洞。同时识别路径上的保护机制（`nonReentrant` / `onlyOwner`），如果存在则终止污点传播。

**实验结果**：Dataset I（23 个真实受害合约）全部检出（Slither 仅检出 12/23），Dataset II（134 vuln + 36,366 non-vuln）检出 129/134，仅 531 FP。在 22,644 个链上合约中检出 20.1% 可能存在重入漏洞。

**与本研究的问题映射**：

实验已揭示 modifier 和跨合约重入是 DeepSeek-chat 持续表现不佳的场景。论文的分析框架为理解这些盲区提供了结构性解释：

| 本研究的顽固 FP/FN | 论文框架下的解释 | 根因 |
|---|---|---|
| modifier_fixed 始终 FP（模型误报 nonReentrant 保护不充分） | Entry point 中 hook 触发不确定——模型不知道 `call{value:...}` 是否会触发回调 | 缺乏标准知识：无法判断外部调用对象类型及其 hook 语义 |
| modifier_insecure 在强约束下全部漏报 | 模型将 `neverReceiveAirdrop` 误认为保护机制 | 缺乏 entry/reentry 分离思维：无法区分"看起来像保护"和"实际上有效保护" |
| cross_contract 场景 Acc 持续偏低 | 跨合约调用链中，被调用合约的标准类型未知 | 无法利用 ERC 标准语义推断跨合约回调路径 |
| crosschain Acc 仅 0.556-0.667 | Bridge 调用不匹配典型重入模板 | 缺乏对非 ERC 标准的专有调用模式知识 |

**可直接借用的三项改进**：

**改进一：在静态分析摘要中注入合约标准语义。** 当前 Slither 摘要仅报告"外部调用 = TUPLE_0(bool,bytes) = LOW_LEVEL_CALL"，未区分调用是否可劫持。借鉴论文的 Table I，可在预处理阶段增强静态分析：

```
当前摘要:
  外部调用=TUPLE_0(bool,bytes) = LOW_LEVEL_CALL, dest:token, function:transferFrom
  写状态=userBalances | 交互后更新状态=True

增强摘要:
  外部调用=token.transferFrom() | 对象类型=ERC777 | hook触发=True (tokensToSend/tokensReceived)
  → [HIJACKABLE] 攻击者可通过 hook 回调重入
  写状态=userBalances | 交互后更新状态=True
```

这需要扩展 `preprocess.py` 中的 Slither 分析，增加外部调用对象的类型推断（从声明语句中提取 `token` 的类型信息），然后查询标准知识库判断是否 hijackable。

**改进二：在 Prompt 中注入标准感知的 Entry/Reentry 判断框架。** 借鉴论文的三组件思想，可以将当前的统一判断 Prompt 重构为结构化的分步分析：

```
步骤 1（Entry Point）：找出所有可劫持的外部调用。
  - 如果被调用对象是 ERC777 类型且方法为 transfer/transferFrom/burn → hijackable
  - 如果被调用对象是 ERC721 类型且方法为 safeTransferFrom → hijackable
  - 如果是低级调用 call{value:...} 且目标是 msg.sender → hijackable
  - 记录每个 hijackable call 之后更新的状态变量（延迟更新变量）

步骤 2（Reentry Point）：找出所有可被回调触发的函数中是否存在可利用操作。
  - Direct: transfer/send/call{value:...} 目标可为 msg.sender
  - Indirect: 修改 Direct 操作依赖的状态变量（如白名单、余额、计数器）

步骤 3（Flow Check）：延迟更新变量是否能影响 Reentry Point 中的可利用操作？
  - 如果能 → 重入漏洞
  - 如果路径上有 nonReentrant/onlyOwner → 无漏洞
```

这种结构化 Prompt 可以与 §5.6 讨论的 Verbose Elaboration 和增强 Self-Inspection 组合使用，形成更完整的上下文注入策略。

**改进三：标准知识库作为 Slither 摘要的语义增强层。** 当前实验发现 Slither 裸报告是噪声（§4.1），但配合 bypass 标签后转化为有效信号（§4.4）。论文的标准知识库可以成为 bypass 之外的**第二种语义增强层**：

```
Slither 裸报告（噪声）
  → + bypass 检测标签 [SAFE]/[BYPASS-RISK]（代码证据）
  → + 标准知识标签 [HIJACKABLE]/[NOT_HIJACKABLE]（语义证据）
  → = 双重增强的上下文
```

这种多层增强与 §5.6 Gas-Wasting 论文的 Verbose Elaboration（从不同视角重复关键概念）形成呼应——bypass 标签提供代码级证据，标准知识标签提供语义级证据，两个维度互补。

**不推荐直接迁移的设计**：

- **完整污点分析引擎**：论文的静态污点分析需要构建 ICFG、控制依赖和数据依赖图，工程复杂度高。LLM 的优势恰恰在于可以"软推理"——通过 Prompt 引导 LLM 模拟污点分析的思考过程，而不需要实现完整的确定性引擎。这也符合本研究"LLM 做推理，规则引擎做验证"的核心方法论。
- **全量静态分析替代 LLM**：论文 100% 基于确定性静态分析，在已知漏洞样本上表现优异（Dataset I 100% 检出），但扩展到未见过的合约时依赖标准覆盖率。LLM 的泛化能力可能补充静态分析无法覆盖的非标准合约场景。

**总结**：Cai et al. (2025) 的启示是合约标准作为先验知识的价值——83% 的链上合约遵循已知标准，标准定义了明确的回调语义。该思路已在 §4.8 的 standards_entry 实验中实现，将标准知识注入 LLM 上下文（预处理增强 + 结构化 Prompt + 标准知识标签），使 modifier Acc 首次达到 1.000。

---

## 结论

本文构建了可复现的重入漏洞检测流水线（消融→切片→Guard→Prompt→绕过检测→RAG→标准增强→组合），从 zero-shot 出发，经 Few-Shot 检索增强、合约标准语义注入，最终以 confidence-gated 组合流水线收束。

**消融实验**：crop_only 的 Acc 最优（0.902），代码裁剪是核心独立增益模块。Slither 裸报告导致退化（0.821），需与 bypass 和 Prompt 规则组合使用。

**切片与 Guard**：reentrancy_slice_v1 压缩 47.9%，Guard 注入补回安全上下文。

**绕过检测与 Prompt 规则**：bypass + Prompt 规则实现 Acc 0.935，FPR 0.250，FNR 0.020。

**RAG 强约束**：借鉴 PropertyGPT 的 MUST/MUST NOT 约束，FPR=0，fixed Acc=1.000。FNR=0.111，modifier 全部漏报。Few-Shot 在判别任务中增加了保守性。

**标准增强**：借鉴 Cai et al. 的 ERC 标准分析，Entry-Reentry-Flow 框架使 modifier Acc 首次达 1.000。cross_contract FPR=1.000。

**confidence-gated 组合**：利用 rag_strong FN 时 confidence=0.0 作为切换信号，Pass 1（rag_strong）+ Pass 2（standards_entry，confidence<0.5 触发）。Acc=0.957，FPR=0，FNR=0.049，2.4% 额外开销。

验证了九条规律：(a) 裁剪优先——去噪是最大增益；(b) 指令优于注释——Prompt 规则优于代码内注释；(c) 证据优于规则——bypass 标签优于文本约束；(d) 约束层级决定行为边界——MUST 约束消除误报强于描述性规则；(e) Few-Shot 在判别任务中是把双刃剑；(f) 反馈信号硬度决定迭代有效性；(g) 语义感知在子任务间收益不对称；(h) confidence 反映模型的知识边界自我感知，可作为架构切换信号；(i) 组件编排优于 Prompt 融合。

---

## 项目结构

### 源文件

| 文件 | 功能 | 使用阶段 |
|---|---|---|
| `src/main.py` | 实验编排主入口，管理 7 轮全部 profile 及 two_pass 流水线 | 全部轮次 |
| `src/preprocess.py` | Slither 静态分析 + 启发式回退 + 代码裁剪 + 匿名化 + 标准增强摘要 | 全部轮次 |
| `src/reentrancy_slice_engine.py` | 4 规则切片引擎（外部调用精确化、函数筛选、显著函数 Top10%、贪心填充）+ Guard 注入 | 第 2–7 轮 |
| `src/run_reentrancy_slice.py` | 批量预计算切片缓存生成器 | 第 2 轮起 |
| `src/rag_engine.py` | RAG 引擎：TF-IDF 向量索引 + 8 条重入模式库 + Few-Shot 检索 | 第 5–7 轮 |
| `src/revision_engine.py` | 迭代修订引擎：JSON 格式诊断 + 置信度反馈修订（最多 3 轮） | 第 5 轮（消融） |
| `src/standards_kb.py` | ERC 标准知识库：合约标准检测 + hook 触发推断 + 外部调用可劫持性分类 | 第 6–7 轮 |
| `src/llm_client.py` | OpenAI 兼容 API 客户端 + JSON 响应解析 | 全部轮次 |
| `src/chain_contract_test.py` | 链上真实案例验证脚本 | 独立 |

### Prompt 模板 → 实验映射

#### 第 1–4 轮（消融 → bypass）

| 模板 | Profile | 实验轮次 |
|---|---|---|
| `baseline_prompt.txt` | `baseline_raw` | 第 1 轮（消融基线） |
| `baseline_prompt_paper.txt` | `crop_only` | 第 1 轮（消融） |
| `baseline_summary_prompt.txt` | `crop_slither`, `reentrancy_slice_v1` | 第 1–4 轮 |
| `cot_reentrancy_paper.txt` | `crop_slither_cot` | 第 1 轮（消融） |
| `multi_contract_summary_prompt.txt` | `crop_slither_multi` | 第 1 轮（消融） |
| `original_*.txt` | 备份（不含 nonReentrant 规则） | 第 1–2 轮原始版本 |

#### 第 5 轮（RAG + 强约束）

| 模板 | Profile | 说明 |
|---|---|---|
| `rag_reentrancy_prompt.txt` | `rag_strong` | MUST/MUST NOT/REMEMBER 强约束，无 Few-Shot |
| `rag_fewshot_prompt.txt` | `rag_fewshot`, `rag_fewshot_revision`, `rag_full` | 强约束 + RAG Few-Shot 检索 |

#### 第 6 轮（标准增强）

| 模板 | Profile | 说明 |
|---|---|---|
| `standards_reentrancy_prompt.txt` | `standards_entry` | Entry-Reentry-Flow 三步框架 + ERC 标准知识 + Verbose Elaboration |

#### 第 7 轮（组合）

| 模板 | Profile | 说明 |
|---|---|---|
| `rag_reentrancy_prompt.txt` + `standards_reentrancy_prompt.txt` | `two_pass` | Pass 1 → rag_strong；confidence<0.5 → Pass 2 standards_entry |
| `combined_reentrancy_prompt.txt` | `combined_surgical` | 两套 Prompt 直接融合（消融失败） |
| `surgical_v2_prompt.txt` | `surgical_v2` | 精简融合模板（消融失败） |

### 数据集与切片

```
contracts/
├── manifest.json                       # 41 样本清单（sample_id → 文件 + label）
├── 02_reentrancy/                      # 标准重入 insecure/fixed 对
├── 03_reentrancy_via_modifier/         # modifier 重入对
├── 04_cross_function_reentrancy/       # 跨函数重入对
├── 05_cross_contract_reentrancy/       # 跨合约重入对
├── crosschain_reentrancy_pairs/        # 跨链场景配对
├── extra_reentrancy_pocs/              # 自定义 PoC
└── smartbugs_curated/                  # 23 个真实链上受害合约

contracts_reentrancy_slice_v1/          # 切片缓存（第 2 轮起）
├── {sample_id}/slice.sol               # 41 个预计算切片
├── global_stats.json                   # 全局函数统计
├── slice_manifest.json                 # 切片路径映射
└── slice_stats.json                    # 压缩统计

runs/                                   # 实验输出（每个 run-id 一个子目录）
├── {run-id}/
│   ├── run_config.json                 # 实验配置
│   ├── repeat_01/02/03/                # 每轮重复独立保存
│   │   ├── {profile}/
│   │   │   ├── {sample_id}/
│   │   │   │   ├── preprocess.json     # 预处理结果
│   │   │   │   ├── prompt.txt          # 组装后的完整 Prompt
│   │   │   │   ├── prediction.json     # LLM 预测结果
│   │   │   │   ├── rag_retrieval.json  # RAG 检索记录（若启用）
│   │   │   │   └── two_pass_meta.json  # Two-Pass 触发记录（two_pass profile）
│   │   │   ├── metrics.json
│   │   │   ├── error_analysis.json
│   │   │   └── scenario_metrics.json
│   │   └── repeat_summary.json
│   ├── summary.json                    # 全量实验汇总
│   └── comparison.json                 # 以 baseline_raw 为基线的对比报告
```

## 快速复现

```bash
pip install -r requirements.txt
export OPENAI_API_KEY="your_key"

# 消融实验（第 1 轮）
python3 src/main.py \
  --backend openai --model deepseek-chat --base-url https://api.deepseek.com \
  --repeat 3 --run-id ablation \
  --profiles baseline_raw crop_only crop_slither crop_slither_cot crop_slither_multi

# RAG 实验（第 5 轮）
python3 src/main.py \
  --backend openai --model deepseek-chat --base-url https://api.deepseek.com \
  --repeat 3 --run-id rag-experiment \
  --profiles crop_slither rag_strong rag_fewshot --rag-enabled --rag-top-k 4 \
  --slice-mode reentrancy_slice_v1

# 标准增强实验（第 6 轮）
python3 src/main.py \
  --backend openai --model deepseek-chat --base-url https://api.deepseek.com \
  --repeat 3 --run-id standards-experiment \
  --profiles crop_slither rag_strong standards_entry --rag-enabled --rag-top-k 4 \
  --slice-mode reentrancy_slice_v1

# Two-Pass 组合实验（第 7 轮）
python3 src/main.py \
  --backend openai --model deepseek-chat --base-url https://api.deepseek.com \
  --repeat 3 --run-id two-pass \
  --profiles crop_slither rag_strong standards_entry two_pass --rag-enabled --rag-top-k 4 \
  --slice-mode reentrancy_slice_v1
```
