# 赛务实例证书的用途隔离与收件交接

设备可有多个采集实例。客户端证书按实例标签在本机签发为演练证书。正式和演练接收方保留各自的会话记录与收件事实。所有记录均为合成资料。

## 合作方输入

- `registry` 对应归属及设备实例登记。
- `authority` 对应赛事用途核准与签发回执。
- `practice` 对应演练端的收件情况。
- `race` 对应正式接收端的收件情况。

`data/observations.jsonl` 每行是一份来件。`record_id` 为本资料集的来件编号，`relates_to` 为与它关联的其他来件，业务对象编号在 `payload` 中。`observed` 是接到来件的时间，来源提供的业务时刻可能早于它。相同业务流水可以有两份记录，后到的一份可能只补充实际收到的时间，`unknown` 表示来源尚不能确认发生与否。时段取含起点、不含终点的区间。样本中自称的动作或待处理请求只表示提出了请求。

样本 `sequence` 由接收域和赛道分别编号。即使两个分域的连接证书都在有效期内，也不说明资料用途相同。`issued_at` 和 `received_at` 来自不同来源。`review_from` 指既有收件授权需要复核的起点。体验和比赛两个信任根在本机分别生成。

## 本地资料端

使用 Python 3.11 标准库，在项目根目录运行。这个端口提供只读合作方资料。

```sh
python3 transcript.py --port 8091
```

`GET /sources` 返回来件来源。`GET /observations` 返回全部已载入的样本，使用 `source` 可按来件方筛选，`through` 可限定截至哪个观测时刻。直接读文件和读接口使用同一数据格式。

```sh
python3 -m unittest -v
```

## 演练证书

本机 OpenSSL 3 可生成证书，私有材料写入已忽略的目录，证书仅在演练中使用。

```sh
python3 fixture_certs.py --output .local/certs --timing
```

每个接入域目录下会写出 `trust.json` 信任清单，列出该信任根下可用的真实 TLS
客户端身份。要查看正式资料端的传输证书方式，可另启一个本地端口。演练资料端
可分别指定 `practice` 或 `race` 信任根。

```sh
python3 transcript.py --port 8092 --cert-dir .local/certs --trust-domain race
curl --cacert .local/certs/race/ca.crt --cert .local/certs/race/timer-r1.crt --key .local/certs/race/timer-r1.key https://127.0.0.1:8092/sources
```

## 赛务接收台（station 包）

`station/` 在合作方资料之上实现按已验证身份、实例用途、赛道与生效段的收件裁决。

- `station/core.py`：登记实例、接入域路由、生产许可、签发状态、撤销与隔离、
  收件裁决、入账账本与交接报告。
- `station/replay.py`：把 `data/observations.jsonl` 按观测时刻重放进引擎。
- `station/receiver.py`：practice 与 race 两个接入域各自的 mTLS 接收端，
  分别加载本域 CA，跨域身份在 TLS 握手阶段即被拒。
- `station/ops.py`：值班员命令行，办理登记、试用、转正、隔离、重放与查询。

裁决把每份来件分入三个互斥的收件事实：

- `blocked`：已防止继续送入（信任不符、用途不符、签发未确认、无生效许可、
  重复序号、隔离或范围撤销）。
- `accepted_pending_review`：已受理但来源授权待复核（如先收到 `unknown`、
  或落在撤销复核起点之后的记录）。
- `accepted`：已稳固受理。

同一 `(接入域, 赛道, 序号)` 只入账一次；回执补查回填同一笔，第二个实例重收
会被拒。证书切换成功与资料交接完毕在 `handover` 报告中是两个独立事实。

### 离线重放与核对

```sh
python3 -m station.ops --state-file .local/station.json replay --data data
python3 -m station.ops --state-file .local/station.json status --domain race
python3 -m station.ops --state-file .local/station.json ledger
python3 -m station.ops --state-file .local/station.json handover --device timer-81
```

### 值班流程：登记 → 试用 → 转正 → 隔离

```sh
S="--state-file .local/demo.json --cert-dir .local/certs"
python3 -m station.ops $S register --device timer-81 --instance r-189 \
  --purpose race --cert-label timer-r2
python3 -m station.ops $S route --route-id route-r --domain race \
  --cert-group race --tracks north south --instances r-189
# 试用：签发状态尚未查清，探测可 TLS 但不具备生产资格
python3 -m station.ops $S cert --label timer-r2 --state unknown --observed 5
python3 -m station.ops $S probe --domain race --cert-label timer-r2 \
  --track north --observed 8
# 转正：签发确认 + 赛事负责人对赛道/生效段的独立许可
python3 -m station.ops $S cert --label timer-r2 --state issued \
  --observed 20 --issued-at 20
python3 -m station.ops $S permit --permit-ref perm/42 --instance r-189 \
  --tracks north --start 20 --until 200 --route route-r --observed 20
# 隔离单台实例，不影响同设备练习实例与整个站点
python3 -m station.ops $S quarantine --instance r-189 --observed 40
```

### 两个接入域的真实 mTLS 接收端

```sh
python3 -m station.ops $S serve --practice-port 8101 --race-port 8102
```

两个接收端共享同一份站点状态与写锁，但各自只信任本域 CA。正式资料用正式域
身份送入，练习资料用练习域身份送入；跨域身份会收到 TLS `unknown CA` 告警。

```sh
curl --cacert .local/certs/race/ca.crt \
  --cert .local/certs/race/timer-r2.crt --key .local/certs/race/timer-r2.key \
  -H 'Content-Type: application/json' \
  -d '{"record_id":"live-1","track":"north","sequence":441,"observed":30}' \
  https://127.0.0.1:8102/v1/samples
```

接收端接口：`GET /v1/whoami`、`GET /v1/ledger`、`GET /v1/intake`、
`POST /v1/probe`、`POST /v1/samples`、`POST /v1/receipts`。练习值班角色
（`timer-p1`）无权访问 race 域；只读角色不能写入。

