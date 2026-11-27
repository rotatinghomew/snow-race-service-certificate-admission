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

要查看正式资料端的传输证书方式，可另启一个本地端口。演练资料端可分别指定 `practice` 或 `race` 信任根。

```sh
python3 transcript.py --port 8092 --cert-dir .local/certs --trust-domain race
curl --cacert .local/certs/race/ca.crt --cert .local/certs/race/timer-r1.crt --key .local/certs/race/timer-r1.key https://127.0.0.1:8092/sources
```
