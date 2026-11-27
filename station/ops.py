"""值班员命令行：办理新实例登记、试用、转正、隔离，并核对收件。

状态保存在一个 JSON 站点文件中；`serve` 同时启动 practice 与 race 两个
接入域的 mTLS 接收端，共享同一份站点状态，各自使用本域信任根。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import threading
from typing import Optional

from .core import Station, FileTrust, StaticTrust
from .replay import replay_file, DEFAULT_GROUPS
from .receiver import build_pair

DEFAULT_STATE = Path(".local/station.json")
DEFAULT_CERTS = Path(".local/certs")


def _load(options) -> Station:
    trust = FileTrust(options.cert_dir) if options.cert_dir else StaticTrust(DEFAULT_GROUPS)
    path = Path(options.state_file)
    if path.exists():
        return Station.load(path, trust=trust)
    return Station(trust=trust)


def _save(options, station: Station) -> None:
    path = Path(options.state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    station.save(path)


def _emit(payload) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def cmd_register(options) -> None:
    station = _load(options)
    installed = station.register(
        device=options.device, instance=options.instance,
        purpose=options.purpose, cert_label=options.cert_label,
        observed=options.observed,
    )
    _save(options, station)
    _emit({"registered": installed.__dict__})


def cmd_route(options) -> None:
    station = _load(options)
    route = station.add_route(
        record_id=options.route_id, domain=options.domain,
        cert_group=options.cert_group, tracks=options.tracks,
        instances=options.instances,
    )
    _save(options, station)
    _emit({"route": route.__dict__})


def cmd_permit(options) -> None:
    station = _load(options)
    permit = station.add_permit(
        permit_ref=options.permit_ref, instance=options.instance,
        tracks=options.tracks, valid_from=options.start,
        valid_until=options.until, route_id=options.route,
        observed=options.observed,
    )
    _save(options, station)
    _emit({"permit": permit.__dict__})


def cmd_cert(options) -> None:
    station = _load(options)
    status = station.record_cert(
        label=options.label, state=options.state,
        observed=options.observed, issued_at=options.issued_at,
    )
    _save(options, station)
    _emit({"certificate": {"label": options.label, **status}})


def cmd_revoke(options) -> None:
    station = _load(options)
    permit = station.revoke(
        permit_ref=options.permit_ref, revoked_at=options.observed,
        review_from=options.review_from, track=options.track,
    )
    _save(options, station)
    if permit is None:
        _emit({"error": "未找到许可", "permit_ref": options.permit_ref})
        raise SystemExit(1)
    _emit({"revoked": permit.__dict__})


def cmd_quarantine(options) -> None:
    station = _load(options)
    installed = station.quarantine(options.instance, options.observed)
    _save(options, station)
    if installed is None:
        _emit({"error": "未登记该实例", "instance": options.instance})
        raise SystemExit(1)
    _emit({"quarantined": installed.__dict__})


def cmd_probe(options) -> None:
    station = _load(options)
    probe = station.probe_connectivity(
        record_id=options.record_id, domain=options.domain,
        cert_label=options.cert_label, track=options.track,
        observed=options.observed,
    )
    _save(options, station)
    _emit({"probe": probe.__dict__})


def cmd_upload(options) -> None:
    station = _load(options)
    item = station.consider_sample(
        record_id=options.record_id, domain=options.domain,
        track=options.track, sequence=options.sequence,
        observed=options.observed, moment=options.observed,
        instance=options.instance, cert_label=options.cert_label,
    )
    _save(options, station)
    _emit({"intake": item.__dict__})


def cmd_receipt(options) -> None:
    station = _load(options)
    item = station.consider_receipt(
        record_id=options.record_id, domain=options.domain,
        track=options.track, sequence=options.sequence,
        observed=options.observed, receipt_ref=options.receipt,
        state=options.state, received_at=options.received_at,
        instance=options.instance, cert_label=options.cert_label,
    )
    _save(options, station)
    _emit({"intake": item.__dict__})


def cmd_replay(options) -> None:
    trust = FileTrust(options.cert_dir) if options.cert_dir else StaticTrust(DEFAULT_GROUPS)
    station = replay_file(options.data, trust=trust)
    _save(options, station)
    _emit({
        "replayed": options.data,
        "blocked": len(station.blocked_items()),
        "pending_review": len(station.review_items()),
        "accepted": len(station.accepted_items()),
        "bookings": len(station.bookings),
    })


def cmd_status(options) -> None:
    station = _load(options)
    _emit({
        "installations": {k: v.__dict__ for k, v in station.installations.items()},
        "certificates": station.certificates,
        "permits": [p.__dict__ for p in station.permits],
        "intake": {
            "blocked": station.blocked_items(options.domain),
            "pending_review": station.review_items(options.domain),
            "accepted": station.accepted_items(options.domain),
        },
    })


def cmd_ledger(options) -> None:
    station = _load(options)
    _emit({"ledger": station.ledger(options.domain)})


def cmd_handover(options) -> None:
    station = _load(options)
    _emit(station.handover_report(options.device))


def cmd_serve(options) -> None:
    if not options.cert_dir:
        raise SystemExit("serve 需要 --cert-dir 指向本地演练证书目录")
    servers = build_pair(
        cert_dir=Path(options.cert_dir), state_path=Path(options.state_file),
        host=options.host, practice_port=options.practice_port,
        race_port=options.race_port,
    )
    for domain, httpd in servers.items():
        print(f"{domain} 接收端 https://{options.host}:{httpd.server_address[1]}", flush=True)
    try:
        for httpd in servers.values():
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
        threading.Event().wait()
    except KeyboardInterrupt:
        for httpd in servers.values():
            httpd.shutdown()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="赛务实例登记与收件交接值班台")
    parser.add_argument("--state-file", default=str(DEFAULT_STATE), help="站点状态文件")
    parser.add_argument("--cert-dir", default=None,
                        help="本地演练证书目录（真实 TLS 信任材料）")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("register", help="登记采集实例")
    p.add_argument("--device", required=True)
    p.add_argument("--instance", required=True)
    p.add_argument("--purpose", choices=("practice", "race"), required=True)
    p.add_argument("--cert-label", required=True)
    p.add_argument("--observed", type=int, default=0)
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("route", help="登记接入域路由")
    p.add_argument("--route-id", required=True)
    p.add_argument("--domain", choices=("practice", "race"), required=True)
    p.add_argument("--cert-group", required=True)
    p.add_argument("--tracks", nargs="+", required=True)
    p.add_argument("--instances", nargs="+", default=[])
    p.set_defaults(func=cmd_route)

    p = sub.add_parser("permit", help="赛事负责人独立确认生产用途")
    p.add_argument("--permit-ref", required=True)
    p.add_argument("--instance", required=True)
    p.add_argument("--tracks", nargs="+", required=True)
    p.add_argument("--start", type=int, required=True)
    p.add_argument("--until", type=int, required=True)
    p.add_argument("--route", required=True)
    p.add_argument("--observed", type=int, default=0)
    p.set_defaults(func=cmd_permit)

    p = sub.add_parser("cert", help="登记证书签发状态")
    p.add_argument("--label", required=True)
    p.add_argument("--state", choices=("issued", "unknown", "revoked"), required=True)
    p.add_argument("--observed", type=int, default=0)
    p.add_argument("--issued-at", type=int, default=None)
    p.set_defaults(func=cmd_cert)

    p = sub.add_parser("revoke", help="撤销错误生产资格")
    p.add_argument("--permit-ref", required=True)
    p.add_argument("--track", required=True)
    p.add_argument("--observed", type=int, required=True)
    p.add_argument("--review-from", type=int, required=True)
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("quarantine", help="隔离单个实例")
    p.add_argument("--instance", required=True)
    p.add_argument("--observed", type=int, required=True)
    p.set_defaults(func=cmd_quarantine)

    p = sub.add_parser("probe", help="验证实例对目标入口的可用性")
    p.add_argument("--record-id", default="probe")
    p.add_argument("--domain", choices=("practice", "race"), required=True)
    p.add_argument("--cert-label", required=True)
    p.add_argument("--track", required=True)
    p.add_argument("--observed", type=int, required=True)
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("upload", help="提交一份采集资料")
    p.add_argument("--record-id", required=True)
    p.add_argument("--domain", choices=("practice", "race"), required=True)
    p.add_argument("--track", required=True)
    p.add_argument("--sequence", type=int, required=True)
    p.add_argument("--observed", type=int, required=True)
    p.add_argument("--instance", default=None)
    p.add_argument("--cert-label", default=None)
    p.set_defaults(func=cmd_upload)

    p = sub.add_parser("receipt", help="提交回执或补查")
    p.add_argument("--record-id", required=True)
    p.add_argument("--domain", choices=("practice", "race"), required=True)
    p.add_argument("--track", required=True)
    p.add_argument("--sequence", type=int, required=True)
    p.add_argument("--receipt", required=True)
    p.add_argument("--state", choices=("received", "unknown"), default="received")
    p.add_argument("--observed", type=int, required=True)
    p.add_argument("--received-at", type=int, default=None)
    p.add_argument("--instance", default=None)
    p.add_argument("--cert-label", default=None)
    p.set_defaults(func=cmd_receipt)

    p = sub.add_parser("replay", help="从合作方资料目录重放全部来件")
    p.add_argument("--data", default="data")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("status", help="查看三类收件与登记状态")
    p.add_argument("--domain", choices=("practice", "race"), default=None)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("ledger", help="查看序号入账账本")
    p.add_argument("--domain", choices=("practice", "race"), default=None)
    p.set_defaults(func=cmd_ledger)

    p = sub.add_parser("handover", help="查看某设备的证书切换与交接事实")
    p.add_argument("--device", required=True)
    p.set_defaults(func=cmd_handover)

    p = sub.add_parser("serve", help="启动两个接入域的 mTLS 接收端")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--practice-port", type=int, default=8101)
    p.add_argument("--race-port", type=int, default=8102)
    p.set_defaults(func=cmd_serve)

    return parser


GLOBAL_FLAGS = ("--state-file", "--cert-dir")


def _normalize_argv(argv: list[str]) -> list[str]:
    """把全局参数（可出现在子命令前后）统一移到参数列表最前。"""
    globals_out: list[str] = []
    rest: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in GLOBAL_FLAGS:
            globals_out.extend([token, argv[index + 1]])
            index += 2
        elif any(token.startswith(flag + "=") for flag in GLOBAL_FLAGS):
            globals_out.append(token)
            index += 1
        else:
            rest.append(token)
            index += 1
    return globals_out + rest


def main(argv: Optional[list[str]] = None) -> None:
    import sys
    raw = list(argv) if argv is not None else sys.argv[1:]
    options = build_parser().parse_args(_normalize_argv(raw))
    options.func(options)


if __name__ == "__main__":
    main()
