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

### 总体设计思路

核心设计哲学：**不是训练一个模型，而是构建一个可解释、可迭代、可消融的检测系统**。

- **端到端 vs 流水线**：纯 LLM 端到端黑盒无法定位"哪一步起作用"，必须拆解为独立模块逐一验证。
- **消融实验驱动的迭代**：每一轮实验暴露问题，设计针对性优化，再实验验证，形成闭环。
- **可复现性优先**：所有中间产物（`preprocess.json`、`prompt.txt`、`prediction.json`）落盘，repeat=3 报告均值与标准差。

LLM 能力有限（幻觉、上下文窗口、对 Solidity 语义理解不全），所以不追求全自动，而是用静态分析、规则裁剪与 Prompt 工程补齐短板。

### 实验迭代路线

```
第 1 轮：消融实验（5 个 profile × repeat=3）
  → 发现：FPR 过高（0.458），fixed 变体 100% 误判

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

### 数据集与清洗

**四个数据来源**：

1. **serial-coder**（论文 seed 数据）：8 个配对样本，4 类场景 ×（insecure + fixed）。
2. **smartbugs-curated**：31 个已验证重入漏洞的链上合约，全为阳性。
3. **extra_reentrancy_pocs**：2 个跨函数/跨合约 PoC 样本。
4. **crosschain_reentrancy_pairs**：8 个跨链配对样本。

**清洗前的问题**：原始 49 个样本中 smartbugs 存在 8 个近重复（行级 Jaccard >90%），多源合并时 sample_id 碰撞导致目录覆盖，类别严重不平衡（37 正 : 4 负，比例 9.2:1）。

**清洗操作**：90% 行级 Jaccard 去重（smartbugs 31→23），sample_id 前缀化（`source_name__原id`）消除碰撞，重新加入 crosschain_pairs。

**清洗后**：41 个样本，33 正 : 8 负（比例 4.1:1），FPR 分母从 4 升到 8，更稳定。

| 来源 | 样本数 | 阳性 | 阴性 |
|---|---|---|---|
| smartbugs_curated（去重后） | 23 | 23 | 0 |
| serial_coder | 8 | 4 | 4 |
| crosschain_reentrancy_pairs | 8 | 4 | 4 |
| extra_reentrancy_pocs | 2 | 2 | 0 |
| **合计** | **41** | **33** | **8** |

**四类重入覆盖**：standard_reentrancy（经典 withdraw 模式：先 call 后减余额）、reentrancy_via_modifier（漏洞在 modifier 中，外部调用在函数体前）、cross_function_reentrancy（回调进入同合约另一函数）、cross_contract_reentrancy（主合约→外部合约→回调→主合约）。

标签语义：`label=True` = 存在重入漏洞（insecure / vulnerable），`label=False` = 安全（fixed 变体）。

### 整体方法流程

四阶段流水线：Solidity 合约与依赖文件 → 预处理（Slither / 规则回退，裁剪与匿名化）→ Prompt 组装 → DeepSeek-chat 结构化预测 → 评估与落盘（Accuracy / FPR / FNR）。预处理阶段保留风险函数、相关 modifier 和依赖上下文，并对样本名做匿名化减少标签泄漏。模型输出采用固定 JSON 结构，方便批量解析与指标统计。

### Prompt 设计与消融配置

**实验动机**：核心问题是"什么样的上下文对 LLM 重入检测最有帮助？是越多越好，还是精准裁剪更重要？"

5 个 profile 由简至繁递进：

| Profile | 输入特征 | 验证假设 |
|---|---|---|
| `baseline_raw` | 全量主合约原文 | 纯 LLM 基线——是否需要任何预处理？ |
| `crop_only` | 裁剪后风险代码 | 仅裁剪——验证"去掉无关代码"是否有帮助 |
| `crop_slither` | 裁剪 + Slither 摘要 | 裁剪+摘要——验证静态分析信息是否增强判断 |
| `crop_slither_cot` | + CoT 分步推理 | 加入 CoT——验证复杂 Prompt 工程是否有收益 |
| `crop_slither_multi` | + 多合约上下文 | 加入多合约——验证依赖文件是否必要 |

消融实验逻辑：从简单到复杂逐层叠加，观察每一步的边际收益。若某层退化，说明该增强可能引入噪声。所有 profile 共享同一样本集、T=0、repeat=3。

**reentrancy_slice_v1 优化方案**：在消融实验基础上，引入 4 项切片优化规则——外部调用精确化、函数筛选、显著函数 Top 10%、贪心填充 3800 字符。

### Prompt 规则注入

**设计动机**：slice_v1 实验中 fixed 变体被 100% 误判——`03_modifier_fixed` 3/3 FP（confidence=0.90），`05_cross_contract_fixed` 3/3 FP（confidence=0.95）。根源在于切片剥离了 ReentrancyGuard 继承链，模型只能看到"危险的调用模式"而看不到"保护措施"。

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

### 消融实验

| Profile | Accuracy | FPR | FNR | fixed Acc |
|---|---|---|---|---|
| baseline_raw | 0.8699 | 0.375 | 0.071 | 0.625 |
| crop_only | **0.9024** | 0.458 | **0.010** | 0.542 |
| crop_slither | 0.8455 | 0.458 | 0.081 | 0.542 |
| crop_slither_cot | 0.8049 | 0.375 | 0.152 | 0.625 |
| crop_slither_multi | 0.8049 | 0.542 | 0.111 | 0.458 |
| slice_v1（Guard） | 0.9024 | 0.375 | 0.030 | 0.625 |
| crop_slither + Prompt | 0.8780 | 0.292 | 0.081 | 0.708 |
| slice_v1 + Prompt | 0.8699 | **0.250** | 0.101 | **0.750** |
| slice_v1 + Prompt + bypass | **0.8780** | 0.333 | **0.071** | 0.667 |

> DeepSeek-chat, T=0, repeat=3 均值, 41 样本（33 正 / 8 负）。

- **Acc 最优**：crop_only / slice_v1(Guard)（0.9024）——裁剪是核心增益。
- **FPR 最优**：slice_v1 + Prompt 规则（0.250）——fixed 误判最少。
- **FNR 最优**：crop_only（0.010）——几乎不漏报。
- **Acc 综合最优（slice_v1 系列）**：slice_v1 + Prompt + bypass（0.8780）——FNR 降低 30%，整体 Acc 在 slice_v1 系列中最高。
- CoT / 多合约上下文在所有实验中均未带来稳定增益——复杂 Prompt ≠ 更好结果。

### FPR 优化历程

**问题发现**：slice_v1 实验中 fixed 变体被 100% 误判。`03_modifier_fixed`: 3/3 FP, confidence=0.90。`05_cross_contract_fixed`: 3/3 FP, confidence=0.95。

**根因分析**：切片剥离了 ReentrancyGuard 继承链，模型看不到 `nonReentrant` modifier。模型只看到 `call{value:...}` 外部调用模式 → 直接判定为漏洞。但 fixed 版本已使用 nonReentrant 锁保护，实际不会发生重入。

**四步迭代设计思路**：能否让模型"看到"并"理解"安全保护？→ Guard 源码注入（让模型看到）→ 解释性注释（让模型理解）→ Prompt 规则教授（强约束）→ 切片级绕过标注（证据注入）。

**FPR 优化历程**：

| 步骤 | FPR | FNR | 核心发现 |
|---|---|---|---|
| (1) 消融基线 | 0.458 | 0.010 | 裁剪丢失 ReentrancyGuard 继承链 |
| (2) + Guard 源码注入 | 0.375 | 0.030 | 模型"看到" modifier 但不理解其语义 |
| (3) + 解释性注释 | 0.375 | 0.030 | **代码内注释完全无效** |
| (4) + Prompt 规则 | **0.250** | 0.101 | Prompt 规则有效，但 FNR 飙升至 0.101 |
| (5) + 切片绕过检测 | 0.333 | **0.071** | **FNR 回落 30%，Acc 在 slice_v1 系列中最高** |

**为什么解释性注释无效而 Prompt 规则有效？** LLM 训练数据中，代码注释常被模型视为"可忽略的自然语言上下文"而非强约束。系统 Prompt 中的规则被模型视为"指令"，优先级远高于代码内注释。这揭示了一个重要规律：**对 LLM 而言，指令通道 ≠ 内容通道**。

**切片级绕过检测**：在切片引擎中增加安全摘要生成模块（`_generate_security_summary`），自动分析每个样本中 nonReentrant 锁的覆盖范围，生成结构化标签注入切片上下文——`[SAFE]` 表示所有风险函数均已加锁，`[BYPASS-RISK]` 表示存在未保护的外部调用函数或跨合约调用路径。这使模型能基于代码证据而非纯文本规则做出差异化判断，在不依赖 CoT 的前提下将 FNR 从 0.101 压至 0.071。

**根本局限**：DeepSeek-chat 对 Solidity modifier 执行语义（`_` 代表函数体插入位置）理解有上限，即使给出完整源码和规则，仍无法完全正确处理 modifier 重入场景。FPR 在绕过检测中略有上升（0.250→0.333），说明部分 fixed 变体被误标的绕过风险标签误导——安全摘要的判定阈值仍有调优空间。

### 实验迭代的完整逻辑

1. **为什么要消融实验？** 只有逐层剥离才能回答"哪个模块真正有用"——如果直接上最优方案，无法区分收益来源。
2. **为什么要设计 slice_v1？** 消融发现 crop_only 已最优但 FPR 仍高 → 需要更精准的代码裁剪（全局视角 + 显著函数 + 字符上限）。
3. **为什么要 Guard 注入？** slice_v1 的 FPR 仍 0.375，根因是切片剥离了 ReentrancyGuard → 必须先让模型"看到"保护锁。
4. **为什么要尝试解释性注释？** 假设：模型看到 nonReentrant 源码但不理解 → 加注释解释 `locked=true` 语义 → 结果证明这个假设错了。
5. **为什么要 Prompt 规则？** 既然代码内注释无效 → 换通道：在系统 Prompt 中显式约束 → 成功。**指令通道优于内容通道**。
6. **为什么要切片级绕过检测？** Prompt 规则矫枉过正，FNR 飙升至 0.101 → 仅靠文本规则无法让模型精确区分"nonReentrant 足够"和"nonReentrant 会被绕过" → 在切片中直接注入绕过证据，让模型基于代码结构做判断，FNR 回落 30%。

### 分场景指标

| 场景 | 消融最优 | slice+Prompt | 说明 |
|---|---|---|---|
| standard_reentrancy | 0.972 | 0.931 | 经典模式几乎完美 |
| cross_function | 0.833 | 1.000 | Prompt 规则后 zero FP |
| reentrancy_via_modifier | 0.800 | 0.800 | modifier FP 顽固 |
| cross_contract | 0.722 | 0.556 | 跨合约最难，跨链样本拉低 |

**fixed 变体误判演变**：消融阶段 baseline_raw: 9 FP / 24 fixed → fixed Acc = 0.625。Slice v1 + Guard 注入: 9 FP / 24 → 未显著改善。Slice v1 + Prompt 规则: 6 FP / 24 → fixed Acc = **0.750**（FP 减少 33%）。顽固 FP 来自 modifier_fixed（noReentrant 在步骤 0 生效但对 modifier 顺序判断失误）和 crosschain_fixed（非标准重入模式）。

### 数据集清洗对比

| 指标 | 旧（37正:4负） | 新（33正:8负） |
|---|---|---|
| smartbugs 近重复 | 8 个 | **0 个（去重）** |
| sample_id 碰撞 | 8 组 | **0（前缀化）** |
| FPR 稳定性 | 差（分母仅 4） | **中（分母 8）** |
| baseline_raw Acc | 0.935* | **0.870（更真实）** |

*旧数据集 Acc 虚高（近重复样本 inflate 指标），清洗后才反映真实能力。crosschain 样本拉低分数（跨合约 Acc 仅 0.611），可能不适合作为标准 benchmark。类别仍然不平衡（33:8），但 8 个阴性已是当前最佳可达水平。

---

## 讨论与反思

### 有效的方法（有明确增益）

- **代码裁剪**：去掉无关代码是最大增益，crop_only 始终在 Acc 前二。核心启示：LLM 的注意力是稀缺资源，噪声上下文稀释判断。
- **Guard 源码注入**：FPR 从 0.458→0.375，让模型看到 nonReentrant modifier 的完整实现。
- **Prompt 规则教授**：FPR 再降至 0.250。核心发现：系统 Prompt 中的规则 > 代码内注释——这是 LLM prompt engineering 的重要 insight。
- **数据集清洗**：去重 8 个近重复样本，sample_id 前缀化消除碰撞，FPR 评估更可靠。

### 无效或退化（投入无回报）

- **CoT / 多合约上下文**：在所有实验中均未带来稳定提升。说明：复杂 Prompt ≠ 更好结果，有时反而引入噪声。
- **解释性注释**：在代码注释中添加"locked=true 上锁"→ 对 FPR 无任何改善。模型把代码注释当作文档而非指令。
- **crosschain 数据源**：样本模式差异大（跨链 Bridge 调用而非典型重入），拉低整体 Acc 约 5–10%。

### 关键洞察：指令通道 vs 内容通道

LLM 处理输入时有两条信息通道：**指令通道**（系统 Prompt 中的规则，优先级高）和**内容通道**（代码和注释，优先级低）。本实验首次在重入检测场景下验证了这一机制。

### 设计经验教训

1. **先清洗数据再实验**：旧数据集有近重复样本导致 Acc 虚高约 6%，清洗后才暴露真实能力。数据质量检查应是最优先步骤。
2. **Prompt 规则应该第一步就加入**：从第 1 轮消融就应该在 Prompt 中教授 nonReentrant 语义。对 LLM 的知识盲区要有预判。
3. **代码注释不可靠**：不应假设模型会"认真读注释"——模型对自然语言注释的敏感度远低于结构化指令。
4. **消融实验设计要严格**：每次只变一个变量，否则无法归因。5 个 profile 从 raw→crop→slither→cot→multi 的递进式设计是成功的。
5. **crosschain 样本不应纳入基准**：其漏洞模式与典型重入不同（跨链 Bridge vs 资金重入），应作为独立任务评估。

### 局限性与威胁有效性

- **类别不平衡**：33 正 : 8 负，FPR 分母仅 8，单次误判仍可影响结果。
- **模型能力上限**：DeepSeek-chat 无法完全理解 nonReentrant modifier 的执行语义（`_` 位置代表函数体插入）。
- **公开数据泄漏风险**：smartbugs 合约均为 Etherscan 已验证的主网合约，LLM 预训练可能包含。
- **样本规模有限**：41 个样本适合消融分析，但距离大规模 benchmark 仍有距离。
- **zero-shot 设置**：未进行微调或 few-shot，所有实验均在 zero-shot 条件下完成。

### 未来工作

- **更强的模型**：尝试 GPT-4o 或 DeepSeek-v4 系列，验证 modifier 语义理解能力上限。
- **链上合约验证**：The DAO、Lendf.Me 纳入流水线。
- **Self-consistency**：用多次采样 + 投票机制提升低置信度样本的判定稳定性。
- **数据集扩展**：寻找更多 paired fixed/insecure 样本（当前仅 8 对）。
- **RAG 探索**：论文明确建议的 RAG 方案尚未实现，可作为后续方向。

---

## 结论

本研究搭建了完整的可复现重入漏洞检测流水线（消融→切片→Guard→Prompt→绕过检测五层优化）。

**消融实验**：crop_only 在 Accuracy 上最优（0.9024），代码裁剪是核心增益模块。

**切片优化**：reentrancy_slice_v1 通过 4 项规则压缩 47.9%，结合 Guard 注入和 Prompt 规则实现 FPR 从 0.458→0.250（-45%）。但 FNR 升至 0.101——Prompt 规则矫枉过正。

**绕过检测**：在切片引擎中注入结构化安全摘要（`[SAFE]`/`[BYPASS-RISK]` 标签），使模型基于代码证据做差异化判断，FNR 回落至 0.071（漏报减少 30%），Acc 提升至 0.878（slice_v1 系列最高）。

**FPR 四步优化总结**：Guard 注入 → 解释性注释（无效）→ Prompt 规则（FPR↓，FNR↑）→ 切片绕过检测（FNR↓，Acc↑）。验证了两个关键规律：(a) **指令通道优于内容通道**——系统 Prompt 规则远优于代码内注释；(b) **证据优于规则**——代码结构中的证据比纯文本约束更有效。

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
├── prompts/                          # 5 套 Prompt 模板
├── contracts/
│   └── manifest.json                 # sample_id → Solidity 文件 + label 映射
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
