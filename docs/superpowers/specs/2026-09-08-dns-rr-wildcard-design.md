# `--dns-rr-ip` 通配（泛解析）设计

日期：2026-09-08
分支：`custom`（个人 fork of chinadns-ng，Zig 0.10.1）

## 目标

为 `--dns-rr-ip`（及共享解析路径的 `--hosts`）新增**通配静态解析**支持：

- `--dns-rr-ip '*.internal.xx.com=192.168.31.204'` 使 `a.internal.xx.com`、`a.b.internal.xx.com` 等各级**子域**解析到指定 IP。
- 保持精确匹配的既有行为与优先级。

## 已确认的需求决策

| 决策点 | 结论 |
| --- | --- |
| 配置入口 | 扩展 `--dns-rr-ip`，不做新选项/新文件 |
| 通配语义 | `*.x` 只匹配 `x` 的**各级子域**，**不覆盖 apex** `x` 本身；apex 需另加一条精确记录 |
| 多通配嵌套 | 最深（特异性最高）匹配优先 |
| 优先级 | 精确记录 > 通配记录 |
| hosts 是否顺带支持 `*.` | 因 `--hosts` 与 `--dns-rr-ip` 共享 `add_ip`，顺带支持（默认采用；若需严格限制可后续在 hosts 路径拦截） |

## 现状（行为基线）

- `local_rr.zig` 只做**精确匹配**：`_name_to_records` 为 `std.StringHashMapUnmanaged(Records)`，key 为 wire 格式域名（不含末尾 null label），value 为 `Records{ ipv4: []RR_A, ipv6: []RR_AAAA }`。
- `find_answer(msg, qnamelen, p_answer_n)` 仅当 qtype 为 A/AAAA 时按完整 qname 精确查表；未命中返回 `null`，查询继续走 tag 分组 / 缓存 / 上游转发。
- 本地命中应答 TTL=0，不加 ipset/nftset，先于 tag 分组/缓存/转发。
- 只定义单族 IP 时，另一族查询返回 NODATA（空 answer）。
- `--dns-rr-ip '<names>=<ips>'` 支持逗号分隔多 name / 多 ip，由 `opt.zig#opt_dns_rr_ip` 循环调用 `local_rr.add_ip(name, ip)`。
- 底层已有 `dns_qname_domains(msg, qnamelen, interest_levels, domains[8], p_domain_end)`（`src/dns.c:562`）：按 label 将 qname 逐级切成至多 8 个 wire 格式**后缀**，`interest_levels` 为位掩码（bit L-1 表示要第 L 级），返回域指针升序（L 升序 = 特异性降序）。

## 设计

### 1. 数据结构

`local_rr.zig` 新增一张通配表，与精确表结构同构：

```zig
/// key = 去掉 `*.` 后的后缀域（wire 格式、不含末尾 null label）
var _wild_name_to_records: std.StringHashMapUnmanaged(Records) = .{};
```

value 复用现有 `Records`，多 IP 去重、A/AAAA 分族行为均不变。

### 2. 解析入口

`add_ip(ascii_name, str_ip)` 开头分支：

- 若 `ascii_name` 以 `*.` 开头：
  - 去掉 `*.` 后的剩余部分必须为非空且合法域名，`ascii_to_wire` 入通配表（key 同样减去末尾 null label）；失败走现有 `opt.print("invalid domain")` 报错路径。
- 否则：原精确表逻辑不变。

`opt.zig` 无需修改：`opt_dns_rr_ip` 的逗号拆分循环天然支持 `*.a,*.b=ip` 与 `*.x=ip1,ip2`。

边界：`*.` 单独出现、`*.` 后为空 → `ascii_to_wire` 对空串失败，报"invalid domain"退出。`*`（无点）或 `a.*.com`（通配不在最左）→ 按普通名字进入 `ascii_to_wire`，因含非法字符 `*` 失败报错，不静默通配。

### 3. 查询匹配（`find_answer` 扩展）

命中顺序：**精确表 → 通配表（由深至浅）**。

```text
if 精确表命中            return Records        // 现有逻辑
if 通配表为空            return null
if qtype 非 A/AAAA       return null           // 与现状一致
qname_domains(msg, qnamelen, interest_levels = levels 2..8, &domains[8], &domain_end)
// 跳过 level 1（level 1 = 完整 qname，精确表已查过） ⇒ 天然不覆盖 apex
for 每个后缀 (level 升序 = 特异性降序):
    if 通配表命中该后缀     return Records        // 最深匹配优先
return null
```

- `interest_levels = 0b1111_1110`（只关心 level 2..8）。`qname_domains` 在 qname 级数 < 2 时返回 0，直接跳过。
- 待查后缀字节区间为 `domains[i][0 .. p_domain_end - domains[i]]`，与通配表 key（wire 格式、无末尾 null）一致。
- 匹配演示（`*.internal.xx.com`，key=`internal.xx.com`）：
  - `a.internal.xx.com`（4 级）→ level 2 = `internal.xx.com` → 命中 ✓
  - `a.b.internal.xx.com`（5 级）→ level 3 = `internal.xx.com` → 命中 ✓
  - `internal.xx.com`（3 级）→ 仅 level 1，通配不查 → 不覆盖 apex ✓
  - 同时存在 `*.b.xx.com` 与 `*.xx.com` 时 → level 2 先于 level 3 命中，`*.b.xx.com` 优先 ✓

通配命中复用现有应答构造路径（`dns.make_reply`），`server.zig` 无需修改。日志沿用 `qlog.local_rr`。

### 4. 保持不变的行为

- TTL = 0；本地应答不加 ipset/nftset。
- qtype 非 A/AAAA（TXT/PTR 等）不查本地表，照旧走上游。
- 本地命中仍先于 tag 分组、dns 缓存、verdict 缓存、上游转发。
- `--dns-rr-ip` 既有格式、comma 语义、日志输出不变。

## 复杂度与性能

通配表仅在精确表未命中且表非空时查询，按 qname 级数最多做 7 次哈希查找，可忽略。

## 涉及的改动文件

- `src/local_rr.zig`：新增 `_wild_name_to_records`；`add_ip` 通配分支；`find_answer` 通配匹配；对应 `test:` 用例。

无其他文件改动（`opt.zig`、`server.zig`、C 侧均不动）。

## 测试

按项目惯例在 `src/local_rr.zig` 加 `pub fn @"test: <name>"`（`zig build -Dtest run` 收集执行）：

1. 子域命中：`*.internal.xx.com=192.168.31.204`，构造 `a.internal.xx.com` A 查询 → 应答含该 IP。
2. apex 不命中：同表下 `internal.xx.com` A 查询 → `find_answer` 返回 null。
3. 嵌套通配最深优先：`*.b.xx.com=1.1.1.1` 与 `*.xx.com=2.2.2.2`，查询 `x.y.b.xx.com` → 得 `1.1.1.1`。
4. 精确优先于通配：精确 `a.internal.xx.com=3.3.3.3` + 通配 `*.internal.xx.com=2.2.2.2`，查询 `a.internal.xx.com` → 得 `3.3.3.3`。
5. 多 IP 与多 name：`*.a,*.b=ip1,ip2` → 两个通配名均返回两个 IP。
6. qtype 非 A/AAAA（如 TXT）：通配表存在也不命中，返回 null。

手动冒烟：`zig build -Dtest run`；再 `zig build run -- -v --dns-rr-ip '*.internal.xx.com=192.168.31.204'` 后 `dig a.internal.xx.com @127.0.0.1 -p 65353` 验证。