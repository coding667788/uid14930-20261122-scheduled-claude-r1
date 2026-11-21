# passkey_audit — 可同步通行密钥登录回执的离线取证裁定器

旧审计器按**服务器接收顺序**比较签名计数，常把合法的多设备登录误判为凭证
异常。本程序离线重审：以可信登记、同步记录、撤销节点、可信偏序与观察窗口
为准，服务器接收顺序仅作旁证，按业务规则重新裁定每条登录回执。

输入是**通过预校验的虚构**登录回执、可信登记与同步记录；断言签名用布尔值
标示，不接入任何真实身份服务。仅使用 Python 3.12 标准库，Windows 原生
CPython 3.12 + CPU 可直接运行。

## 运行

```console
python -m passkey_audit CASE.json
```

在仓库根目录（包含 `passkey_audit/` 的目录）执行。报告以确定的 UTF-8 JSON
写到标准输出（键排序、缩进固定，同一输入必然产生同一输出）。

退出码：

| 退出码 | 含义 |
|---|---|
| 0 | 裁定完成（`status: "ok"`） |
| 1 | 固定记录本身冲突，无可行解释（`status: "infeasible"`） |
| 2 | 输入格式或 IO 错误（`status: "error"`） |

运行测试：

```console
python -m unittest discover -s tests -v
```

## 模型与业务规则

- **代次与副本实例**：凭证有独立的登记代次（`generation`）。一个代次可有
  多个可用副本；副本 ID（`copy`）可在更换设备后重新出现，但**设备实例不
  能混用**——每条回执必须分配到与证据相符的一个**副本实例**
  （`instances[].id`）。不同实例互不共享计数空间。
- **去重分组**：同一登录失去确认后的接收重试，以原请求指纹
  （`fingerprint`）去重。同指纹回执构成一个逻辑登录事件（组），整组同留
  同弃；组可保留的前提是组内计数一致、签名与挑战绑定全部有效、候选实例
  交集非空、观察窗口交集非空。
- **候选实例**：给定 `copy` 的回执，候选为该副本 ID 的全部登记实例；未给
  定副本的回执由 `candidates` 提供有限候选集合（每条最多 3 个）。
- **计数规则**：每个实例的正计数沿恢复出的全局事件序**严格上升**（不要求
  连续）；同实例同正计数不可调和。计数为零只许可出现在明确登记为
  `counterless` 的实例上；无计数器实例也不能出具正计数。
- **可信偏序与观察窗口**：`trusted_order` 给出不同可信来源的事件偏序，
  `window` 给出回执的观察期限，两者叠加为差分约束；服务器接收顺序
  （`recv_seq`）不参与可行性判定，仅在见证中报告 `recv_order_agrees`
  作为旁证。
- **同步记录**：`syncs` 记录一次同步创建的新副本（`child`），绑定父实例
  （`parent`）及父已发出的某次回执（`parent_receipt`）。父回执保留且确在
  父实例上时，子实例继承其计数为**下界**（子实例计数必须严格大于父回执
  计数），且事件序为 父回执 ≺ 同步 ≺ 子实例回执。**未完成的同步依赖**
  （父回执被剔除，或未分配到父实例）时，继承下界不成立，子实例按无下界
  的新副本处理；同步事件本身作为可信记录仍然存在，子实例回执仍须位于同
  步之后。
- **撤销节点**：`revocations` 登记某实例的撤销。跨过撤销节点的回执不能再
  用该副本——分配到该实例的保留回执必须全部位于撤销节点之前。
- **硬性无效**：缺失签名（`signature_ok: false`）或非法挑战绑定
  （`challenge_ok: false`）的回执不可用任何排序补救，必然剔除。
- **固定与可剔除**：`fixed: true` 的回执必须真实（所有恢复都保留）；其余
  回执可因观测错误剔除，剔除代价为 `cost`（组代价为成员之和，条数按回执
  计）。

## 输入格式

```json
{
  "case": "名称（可选）",
  "instances": [
    {"id": "I1", "copy": "C1", "generation": "G1", "counterless": false}
  ],
  "receipts": [
    {
      "id": "R1",                 // 回执 ID（事件命名空间内唯一）
      "fingerprint": "F1",        // 原请求指纹（重试去重键）
      "counter": 3,               // 签名计数，>= 0 的整数
      "signature_ok": true,       // 断言签名布尔标示
      "challenge_ok": true,       // 挑战绑定布尔标示
      "copy": "C1",               // 与 candidates 二选一
      "candidates": ["I1", "I2"], // 未给定副本时的候选实例（1..3 个）
      "fixed": false,             // 是否必须真实（默认 false）
      "cost": 1,                  // 剔除代价（默认 1）
      "recv_seq": 12,             // 服务器接收序号（可选，仅旁证）
      "window": [10, 20]          // 观察期限（可选）
    }
  ],
  "syncs": [
    {"id": "S1", "child": "I3", "parent": "I1", "parent_receipt": "R2"}
  ],
  "revocations": [
    {"id": "V1", "instance": "I2"}
  ],
  "trusted_order": [["R1", "S1"], ["S1", "R9"]]
}
```

`syncs`、`revocations`、`trusted_order` 可缺省（视为空）。回执、同步、撤销
的 ID 共用事件命名空间，不得重复；`trusted_order` 引用回执 ID 时按指纹归
并到去重组，两端同属一次登录视为格式错误。

## 输出格式

```json
{
  "schema": "passkey-audit/1",
  "case": "名称",
  "status": "ok | infeasible | error",
  "receipts": {
    "R1": {
      "verdict": "kept_in_all | kept_in_some | kept_in_none",
      "group": "F1",
      "detail": "FORCED",
      "witness": { ... } 
    }
  },
  "optimal": {
    "drop_cost": 8,
    "drop_count": 3,
    "anomaly_set": ["R25", "R34", "R36"],
    "necessary_anomalies": ["R25", "R34", "R36"],
    "optimal_count": 1,
    "optimal_count_capped": false,
    "witness": { ... }
  },
  "conflict": null
}
```

### 报告一：逐条回执判定（`receipts`）

- `kept_in_all`：所有可行恢复都保留（`detail: FORCED`）；
- `kept_in_some`：只在部分恢复中保留（`detail: CONTINGENT`）；
- `kept_in_none`：无可行恢复能保留，`detail` 给出原因：
  `HARD_INVALID_SIGNATURE`、`HARD_INVALID_CHALLENGE`、
  `GROUP_COUNTER_MISMATCH`（同指纹重试计数不一致）、
  `GROUP_WINDOW_EMPTY`（窗口交集为空）、`NO_CANDIDATE`（无相符实例）、
  `CONFLICTS_WITH_FIXED`（与固定记录/可信约束冲突）、
  `NO_FEASIBLE_RECOVERY`（输入整体无可行解释）。

保留的见证（`witness`）给出一套自洽的恢复：`assignment`（去重组 → 副本
实例）、`order`（全局事件顺序）、`times`（满足偏序与窗口的一组逻辑时
刻）、`kept`/`dropped`（回执列表）、`recv_order_agrees`（与服务器接收
顺序是否一致，仅旁证）。

### 报告二：最小异常集（`optimal`）

能解释剩余记录的最小异常集：先按**剔除代价总和**最小，再按**条数**最少，
最后按**升序回执 ID** 字典序决胜，结果为 `anomaly_set`。`optimal_count`
为达到最优（代价、条数）的解释套数（超过 10000 时截断并置
`optimal_count_capped`）；有多套等价解释时，`necessary_anomalies` 列出在
**所有**最优解释里都必然异常的记录（可能为空）。

无可行解释时（`status: "infeasible"`），`optimal` 为 `null`，
`conflict.fixed_conflicts` 给出一个子集极小的冲突固定记录集合。

### 格式错误（`status: "error"`）

```json
{"schema": "passkey-audit/1", "status": "error",
 "errors": [{"path": "$.receipts[0].counter", "code": "E_RANGE",
             "message": "counter must be >= 0"}]}
```

错误码：`E_JSON`（JSON 解析失败）、`E_SCHEMA`（结构缺失）、`E_TYPE`
（类型不符）、`E_RANGE`（数值越界/窗口倒置/候选数超限）、`E_DUP_ID`、
`E_UNKNOWN_REF`（引用未知 ID）、`E_EVIDENCE`（`copy` 与 `candidates`
须恰给一个）、`E_TRUSTED_SELF`（偏序自环）、`E_SEMANTIC`（同步父子相
同）、`E_IO`（文件不可读）。

## 随附案例（`cases/`）

| 文件 | 复现场景 |
|---|---|
| `reordered_inbox.json` | 倒序收件但可解释：接收顺序仅旁证，全部保留 |
| `shared_counter_clones.json` | 同计数由不同副本签发：不同实例计数空间各自独立 |
| `generation_mixup.json` | 身份更换后副本 ID 重现：禁止跨代次错误串代（旧代次已撤销，新代次重新计数） |
| `dependent_verdict.json` | 合法回执 RB 的异常判定完全取决于固定记录 RA |
| `tied_optima.json` | 最低代价解有两套，但必要异常集为空 |
| `sync_bound.json` | 同步继承下界：子副本计数不得超过继承点之前的值 |
| `fixed_conflict.json` | 固定记录互相冲突，无可行解释，指出冲突集合 |
| `fleet36.json` | 规模案例：36 条回执、8 个实例、两个代次，含同步、撤销、无计数器实例、接收重试去重、硬性无效与跨代次歧义 |

## 正确性核对

`passkey_audit/brute.py` 是与引擎**独立**实现的穷举核对器：枚举全部
「保留子集 × 副本分配」组合并逐一检查全部约束。测试
（`tests/test_passkey_audit.py`，`python -m unittest discover -s tests`）
将引擎与穷举器在全部小案例及 150 组随机小案例上交叉核对（逐条判定、最
小异常集、必要异常、最优解释计数均一致），并对见证做线性扩展、计数递
增、同步下界、撤销截止的一致性校验。

## 实现与限制

- 求解器为带回溯的约束搜索：按「选项最少优先」顺序决策每个去重组的
  保留/剔除与实例分配，增量维护偏序图（拓扑排序判环）与观察窗口差分约
  束（Bellman-Ford 判可行）进行剪枝；最小异常集用分支限界，必要异常用
  带预算的可行性查询。
- 规模上限按 36 条回执、8 个副本实例、每条最多 3 个候选实例设计；随附
  的 36 条规模案例完整裁定约 0.2 秒。病态输入（大量高歧义可剔除回执）
  下搜索可能指数级增长，这是该判定问题本身的性质。
