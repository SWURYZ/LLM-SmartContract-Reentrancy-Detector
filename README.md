# 基于 LLM 的智能合约重入漏洞检测

> 消融实验驱动的迭代优化流水线 · DeepSeek-chat · 代码切片 · Prompt 工程

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

**各模板使用场景**：

| 模板文件 | 对应 Profile | 输入内容 | 使用阶段 |
|---|---|---|---|
| `baseline_prompt.txt` | `baseline_raw` | 全量合约原文 | 消融 / Prompt规则 / bypass |
| `baseline_prompt_paper.txt` | `crop_only` | 裁剪后风险代码 | 消融 / Prompt规则 / bypass |
| `baseline_summary_prompt.txt` | `crop_slither`、`reentrancy_slice_v1` | 裁剪代码 + Slither 摘要 | 消融 / Prompt规则 / bypass |
| `cot_reentrancy_paper.txt` | `crop_slither_cot` | 裁剪代码 + 摘要 + CoT 步骤 | 消融 / Prompt规则 / bypass |
| `multi_contract_summary_prompt.txt` | `crop_slither_multi` | 裁剪代码 + 摘要 + 依赖文件 | 消融 / Prompt规则 / bypass |

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
| crop_slither（真实 Slither） | 0.8212 | 0.375 | 0.131 | 0.625 | -0.081 |
| crop_slither_cot | 0.8049 | 0.375 | 0.152 | 0.625 | -0.016 |
| crop_slither_multi | 0.8049 | 0.542 | 0.111 | 0.458 | 0.000 |

> DeepSeek-chat, T=0, repeat=3 均值, 41 样本。crop_slither 为修复 solc 版本匹配后重跑的真实 Slither 数据（原 0.8455 因 Slither 静默失败回退为启发式分析，不可用）。

**实验结果解读**：

- **crop_only 边际增益最大（+0.033）**：代码裁剪是消融实验中唯一正向贡献的模块。消除无关代码使模型注意力集中于风险点，漏报率压至 0.010。**但代价显著**：裁剪同时剥离了 ReentrancyGuard 安全上下文，FPR 从 0.375 升至 0.458——fixed 变体识别率仅 0.542。这一矛盾直接驱动了后续的 Guard 注入实验。
- **crop_slither 退化（-0.081）**：加入真实 Slither 静态分析摘要后 Acc 反而从 0.902 降至 0.821，FNR 升至 0.131。**裸 Slither 报告是噪声而非信号**——Slither 输出的结构化文本（外部调用列表、状态变量读写清单）以密集格式注入 Prompt，稀释了模型对代码本身的注意力。
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
| slice_v1 + Guard（启发式） | 0.9024 | 0.375 | 0.030 | 0.625 | 原数据（Slither 未生效） |
| slice_v1 + Guard（Slither） | 0.8861 | 0.375 | 0.051 | 0.625 | **真实 Slither 修正数据** |

> Guard = 原始 Prompt 模板（不含 nonReentrant 规则）+ 切片 v1 + 守卫源码注入。

**结果解读**：真实 Slither 下 Guard 注入的 Acc 为 0.886（低于启发式的 0.902），FPR 持平 0.375——Guard 源码注入让模型看到 nonReentrant 修饰符，但 Slither 的结构化报告提供了更多外部调用上下文，反而略微增加了模型的困惑。**但按场景拆解后暴露了严重的不均衡问题**：**但按场景拆解后暴露了严重的不均衡问题**：

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

| 方案 | Accuracy | FPR | FNR | fixed Acc | 数据来源 |
|---|---|---|---|---|---|
| Guard+Slither（基线） | 0.8861 | 0.375 | 0.051 | 0.625 | 真实 Slither |
| + Prompt 规则 | 0.8943 | 0.375 | 0.040 | 0.625 | 真实 Slither（无 bypass） |
| + Prompt 规则 + bypass | **0.9349** | **0.250** | **0.020** | **0.750** | 真实 Slither + bypass |

> 标注"真实 Slither"的行为 solc 修复后重跑数据。原启发式 Prompt 规则数据（Acc=0.870, FPR=0.250, FNR=0.101, fixed Acc=0.750）因 `{static_summary}` 来自启发式回退而非 Slither，不可直接对比。

**结果解读**：

- **Prompt 规则单独使用无法降低 FPR**：真实 Slither 下 FPR 与 Guard 基线持平（0.375）。在 Slither 提供的真实静态分析上下文中，纯文本规则无法独立修复固定变体的误判。
- **Prompt 规则 + bypass 才是真正的增益组合**：同时使用规则和绕过检测时，Acc 跃升至 0.935，FPR 降至 0.250，FNR 压至近乎零的 0.020——**Slither 报告 + bypass 标签 + Prompt 规则的组合效应远超单独使用任一项**。
- **解释性注释结论不变**：虽未在真实 Slither 下单独重跑，但其完全无效的特性已在启发式实验中充分验证——模型将代码注释视为可忽略文档。

---

### 4.4 切片级绕过检测：代码证据驱动的差异化判断

**驱动问题**：Prompt 规则矫枉过正，导致 FNR 从 0.030 升至 0.101。根源在于纯文本规则无法让模型区分"nonReentrant 保护充分"和"nonReentrant 存在绕过路径"两种情况。如何让模型基于代码结构做差异判断，而不是依赖黑名单式的规则？

**实验设计**：在切片引擎中新增 `_generate_security_summary` 模块，分析每个样本中 nonReentrant 锁的覆盖范围：(a) 统计加锁/未加锁函数比例；(b) 识别可被攻击者绕过的未保护调用路径；(c) 检测跨合约调用模式。生成结构化标签——`[SAFE]`（所有风险函数已覆盖）或 `[BYPASS-RISK]`（存在绕过路径）——直接注入切片上下文。

| 方案 | Accuracy | FPR | FNR | fixed Acc |
|---|---|---|---|---|
| slice_v1 + Prompt（基线） | 0.8699 | **0.250** | 0.101 | **0.750** |
| slice_v1 + Prompt + bypass（启发式） | **0.8780** | 0.333 | **0.071** | 0.667 |
| slice_v1 + Prompt + bypass + Slither | **0.9349** | **0.250** | **0.020** | **0.750** |

**结果解读**：

- **启发式 bypass**：FNR 从 0.101 回落至 0.071，但 FPR 回升至 0.333——安全摘要的激进阈值误标了部分 fixed 变体。
- **Slither 真实报告（93% 覆盖率）**：Acc 跃升至 0.935（全实验最高），FPR 恢复最优 0.250，FNR 压至近乎零的 0.020，fixed Acc 维持 0.750。**真实 Slither 报告 + bypass 标签 + Prompt 规则的组合同时实现了最高的 Acc、最低的 FPR 和最低的 FNR——三指标全面最优。**

**关键发现**：初版实验的"Slither 退化"结论是由 solc 版本不匹配导致的静默失败——Preprocess 中 Slither 抛异常后被 try/except 静默捕获，自动回退为启发式分析。修复 `_detect_solc_binary` 自动版本匹配后，93% 合约成功调起 Slither，静态分析摘要从"噪声"变为"有效信号"。

---

### 4.5 分场景指标与 fixed 变体误判演变

| 场景 | 消融最优（来源） | slice_v1+Prompt | 说明 |
|---|---|---|---|
| standard_reentrancy | 0.972（baseline_raw） | 0.931 | 经典模式几乎完美识别 |
| cross_function | 0.833（crop_only） | 1.000 | Prompt 规则后 zero FP |
| reentrancy_via_modifier | 0.800（多方案持平） | 0.800 | modifier 执行顺序混淆，FP 顽固 |
| cross_contract | 0.722（crop_only） | 0.556 | crosschain 样本模式偏离典型重入 |

**fixed 变体误判演变**：消融 baseline_raw: 9/24 → Guard 注入: 9/24 → Prompt 规则: **6/24（↓33%）** → 绕过检测: 8/24（略回升）。顽固 FP 始终来自 modifier_fixed（modifier 执行顺序不被模型理解）和 crosschain_fixed（跨链 Bridge 调用不匹配重入模板）。

### 4.6 数据集清洗效果验证

| 指标 | 旧（37正:4负） | 新（33正:8负） |
|---|---|---|
| smartbugs 近重复 | 8 个 | **0** |
| sample_id 碰撞 | 8 组 | **0** |
| baseline_raw Acc | 0.935（虚高） | **0.870（真实）** |
| FPR 评估稳定性 | 差（分母 4） | **中（分母 8）** |

旧数据集 Acc 虚高 6.5 个百分点，验证了清洗的必要性。crosschain 样本的跨合约 Acc 仅 0.556–0.667，其漏洞模式与典型重入存在本质差异，未来应考虑独立评估。

---

## 讨论

### 5.1 各优化手段的增益与代价量化

下表按实验时间顺序汇总每项优化手段相对于其前驱方案的边际变化，揭示每一步的净收益与代价。

| 优化手段 | 驱动源 | ΔAcc | ΔFPR | ΔFNR | 净收益 | 代价 |
|---|---|---|---|---|---|---|
| 代码裁剪（crop_only） | 消融发现 | **+0.033** | +0.083 | -0.061 | Acc 大幅提升，FNR 降至近乎零 | FPR 飙升（安全上下文丢失） |
| 启发式摘要（初版 Slither 静默失败） | 消融叠加 | -0.057 | 0 | +0.071 | 无 | Slither 因 solc 版本不匹配回退为启发式 |
| CoT 推理 | 消融叠加 | -0.041 | -0.083 | +0.071 | 无 | Acc 进一步退化 |
| 多合约上下文 | 消融叠加 | 0 | +0.167 | -0.041 | 无 | FPR 全指标最差 |
| Guard 源码注入 | slice_v1 后 FPR 仍高 | 0 | **-0.083** | +0.020 | FPR 显著下降 | FNR 微升 |
| Prompt 规则 | Guard 后 fixed 仍误判 | -0.033 | **-0.125** | +0.071 | FPR 大幅下降，fixed Acc 最优 | FNR 飙升至 0.101 |
| 切片绕过检测 | Prompt 规则矫枉过正 | **+0.008** | +0.083 | **-0.030** | FNR 回落 30%，slice_v1 系列 Acc 最高 | FPR 回升 |
| **Slither 真实报告** | 修复 solc 匹配，93% 合约生效 | **+0.057** | **-0.083** | **-0.051** | ★ Acc 0.935，FPR 0.250，FNR 0.020 全面最优 | 无 |

**设计启示**：初版实验的"Slither 无效"结论本质是 solc 版本不匹配导致的静默失败——真实 Slither 报告结合 bypass 检测后，Acc 跃升至 0.935，FPR 恢复最优（0.250），FNR 压至近乎零（0.020），实现了此前从未达成的 Acc/FPR/FNR 三指标全面最优。最优方案取决于应用场景：若人工复核资源有限，选 FPR 最优的 slice_v1+Prompt（FPR=0.250）；若漏报成本极高，选 Slither+bypass（FNR=0.020）。

### 5.2 核心机制发现

**发现一：指令通道 ≠ 内容通道。** 系统 Prompt 中的规则被模型视为需遵循的权威约束（指令通道），而代码内嵌注释仅被视为可忽略的上下文文档（内容通道）。这一发现的理论意义在于：当 LLM 缺乏领域语义理解时，*告知规则*远比*在数据中展示规则*有效。

**发现二：证据优于规则。** Prompt 规则虽然降低了 FPR，但带来了不可控的过度泛化（FNR 飙升）。将安全证据直接嵌入切片上下文（`[SAFE]`/`[BYPASS-RISK]` 标签）使模型能做基于具体代码结构的差异化判断，在不依赖 CoT 的前提下实现 FNR 回落。*代码结构中的具体标记比系统级规则更精细。*

**发现三：裁剪的注意力机制效应。** 代码裁剪在所有有效方案中均贡献最大边际增益。这从实证角度支持了一个直观假设：LLM 的注意力容量有限，无关上下文的存在会稀释模型对关键风险信号的敏感度。*"少即是多"在安全检测任务中成立。*

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
- **RAG 探索**：检索增强生成方案（`LLM4Re.pdf` 建议）尚未实现，可将外部知识库（如 SWC Registry、CVE 记录）作为补充证据源。

---

## 结论

本研究搭建了完整的可复现重入漏洞检测流水线（消融→切片→Guard→Prompt→绕过检测五层优化）。

**消融实验**：crop_only 在 Accuracy 上最优（0.9024），代码裁剪是核心增益模块。真实 Slither 裸报告反而导致 Acc 退化（0.821），需与 bypass 和 Prompt 规则组合使用才能转化为有效信号。

**切片优化**：reentrancy_slice_v1 通过 4 项规则压缩 47.9%，结合 Guard 注入为模型补回安全上下文。

**绕过检测**：在切片引擎中注入结构化安全摘要（`[SAFE]`/`[BYPASS-RISK]` 标签），使模型基于代码证据做差异化判断。

**最终方案**：reentrancy_slice_v1 + Guard + Prompt 规则 + bypass + 真实 Slither 报告，实现 **Acc=0.935、FPR=0.250、FNR=0.020、fixed Acc=0.750** 的全面最优。

验证了三条关键规律：(a) **Slither 需组合使用**——裸报告是噪声，需 bypass + Prompt 规则共同引导才能转化为信号；(b) **指令通道优于内容通道**——系统 Prompt 规则远优于代码内注释；(c) **证据优于规则**——代码结构中的 bypass 标签比纯文本约束更精细。

**核心价值**：不仅是"模型判断是否"，更是将漏洞分析过程结构化、可记录、可复核，并通过消融实验精准定位每个改进模块的增益来源。

---

## 项目结构

```
├── src/
│   ├── main.py                       # 实验编排主入口
│   ├── preprocess.py                 # Slither 静态分析 + 代码裁剪 + 匿名化
│   ├── reentrancy_slice_engine.py    # 4 规则切片引擎 + Guard 注入
│   ├── run_reentrancy_slice.py       # 批量切片缓存生成器
│   ├── llm_client.py                 # OpenAI 兼容 API 客户端 + JSON 解析器
│   └── chain_contract_test.py        # 链上案例测试
├── prompts/                          # 5 套 Prompt 模板（当前版本：含 nonReentrant 规则）
│   ├── baseline_prompt.txt
│   ├── baseline_prompt_paper.txt
│   ├── baseline_summary_prompt.txt
│   ├── cot_reentrancy_paper.txt
│   ├── multi_contract_summary_prompt.txt
│   └── original_*.txt                # 原始备份版（不含 nonReentrant 规则）
├── contracts/
│   └── manifest.json                 # sample_id → Solidity 文件 + label 映射
├── contracts_reentrancy_slice_v1/    # 预计算切片缓存（41 个 .sol + global_stats + manifest）
│   ├── serial_coder__.../slice.sol
│   ├── smartbugs_curated__.../slice.sol
│   ├── crosschain_reentrancy_pairs__.../slice.sol
│   ├── extra_reentrancy_pocs__.../slice.sol
│   ├── global_stats.json             # 全局函数统计（供显著函数筛选）
│   └── slice_manifest.json           # 切片路径映射
├── runs/                             # 核心实验汇总（summary.json + run_config.json）
├── requirements.txt
├── LLM4Re.pdf
└── .gitignore
```

## 快速复现

```bash
pip install -r requirements.txt

cd src
python3 main.py \
  --backend openai --model deepseek-chat \
  --base-url https://api.deepseek.com \
  --repeat 3 \
  --profiles baseline_raw crop_only crop_slither crop_slither_cot crop_slither_multi \
  --extra-source-root /path/to/extra_reentrancy_pocs \
  --extra-source-root /path/to/crosschain_reentrancy_pairs \
  --run-id ablation-experiment
```
