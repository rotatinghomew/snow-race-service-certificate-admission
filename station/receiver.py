"""两个接入域各自的 mTLS 接收端。

每个接收端只加载本域信任根：practice 域的 CA 签出的身份无法通过 race 域的
TLS 握手，反之亦然。应用层在 TLS 已验证身份之上，再按实例、用途、赛道与
生效段决定资料允许进哪里。
"""
from __future__ import annotations

from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import ssl
import threading
from typing import Optional

from .core import (
    Station, FileTrust, Trust,
    REVIEW, ACCEPTED,
)

# 值班角色：练习值班员无权看正式赛道
ROLE_BY_LABEL = {
    "timer-p1": "practice_duty",
    "timer-r1": "race_duty",
    "timer-r2": "race_duty",
    "timer-r3": "race_duty",
    "localhost": "viewer",
}
READ_ONLY_ROLES = {"viewer"}
PRACTICE_ONLY_ROLES = {"practice_duty"}


class ReceiverServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler_factory, domain: str, station: Station,
                 state_path: Optional[Path], lock: threading.Lock):
        super().__init__(address, handler_factory)
        self.domain = domain
        self.station = station
        self.state_path = state_path
        self.state_lock = lock


def _peer_label(handler: BaseHTTPRequestHandler) -> Optional[str]:
    """从已完成的 mTLS 握手取出对端证书 CN。"""
    cert = handler.connection.getpeercert()
    if not cert:
        return None
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def make_handler(domain: str):
    class ReceiverHandler(BaseHTTPRequestHandler):
        server: ReceiverServer

        def log_message(self, *args):  # 静默，测试输出保持干净
            pass

        def _reply(self, status: int, body: dict):
            encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _identity(self) -> tuple[Optional[str], str]:
            label = _peer_label(self)
            if label is None:
                return None, "anonymous"
            return label, ROLE_BY_LABEL.get(label, "viewer")

        def _role_allowed(self, role: str, write: bool) -> Optional[int]:
            if role == "anonymous":
                return 401
            if role in PRACTICE_ONLY_ROLES and self.server.domain != "practice":
                # 练习值班员无权看正式赛道
                return 403
            if write and role in READ_ONLY_ROLES:
                return 403
            return None

        def _read_json(self) -> Optional[dict]:
            length = int(self.headers.get("Content-Length", 0))
            if not length:
                return {}
            try:
                return json.loads(self.rfile.read(length).decode("utf-8"))
            except json.JSONDecodeError:
                return None

        def do_GET(self):
            label, role = self._identity()
            denied = self._role_allowed(role, write=False)
            if denied is not None:
                self._reply(denied, {"message": "角色无权访问该接入域"})
                return
            station = self.server.station
            if self.path == "/v1/whoami":
                self._reply(200, {
                    "domain": self.server.domain,
                    "cert_label": label,
                    "role": role,
                })
                return
            if self.path == "/v1/ledger":
                self._reply(200, {
                    "domain": self.server.domain,
                    "ledger": station.ledger(self.server.domain),
                })
                return
            if self.path == "/v1/intake":
                self._reply(200, {
                    "domain": self.server.domain,
                    "blocked": station.blocked_items(self.server.domain),
                    "pending_review": station.review_items(self.server.domain),
                    "accepted": station.accepted_items(self.server.domain),
                })
                return
            self._reply(404, {"message": "未找到资料入口"})

        def do_POST(self):
            label, role = self._identity()
            denied = self._role_allowed(role, write=True)
            if denied is not None:
                self._reply(denied, {"message": "角色无权写入该接入域"})
                return
            payload = self._read_json()
            if payload is None:
                self._reply(400, {"message": "请求体应为 JSON"})
                return
            station = self.server.station
            with self.server.state_lock:
                if self.path == "/v1/probe":
                    probe = station.probe_connectivity(
                        record_id=payload.get("record_id", "probe"),
                        domain=self.server.domain,
                        cert_label=label,
                        track=payload["track"],
                        observed=payload["observed"],
                        tls_accepted=True,  # 能完成握手即 TLS 已接受
                    )
                    self._persist()
                    self._reply(200, asdict(probe))
                    return
                if self.path == "/v1/samples":
                    item = station.consider_sample(
                        record_id=payload["record_id"],
                        domain=self.server.domain,
                        track=payload["track"],
                        sequence=payload["sequence"],
                        observed=payload["observed"],
                        moment=payload.get("moment", payload["observed"]),
                        cert_label=label,
                    )
                    self._persist()
                    self._reply(self._status_for(item), asdict(item))
                    return
                if self.path == "/v1/receipts":
                    item = station.consider_receipt(
                        record_id=payload["record_id"],
                        domain=self.server.domain,
                        track=payload["track"],
                        sequence=payload["sequence"],
                        observed=payload["observed"],
                        receipt_ref=payload["receipt"],
                        state=payload.get("state", "received"),
                        received_at=payload.get("received_at"),
                        cert_label=label,
                    )
                    self._persist()
                    self._reply(self._status_for(item), asdict(item))
                    return
            self._reply(404, {"message": "未找到资料入口"})

        @staticmethod
        def _status_for(item) -> int:
            if item.status == ACCEPTED:
                return 202
            if item.status == REVIEW:
                return 202
            return 423  # Locked：已防止继续送入

        def _persist(self):
            if self.server.state_path is not None:
                self.server.station.save(self.server.state_path)

    return ReceiverHandler


def server_ssl_context(cert_dir: Path | str, group: str) -> ssl.SSLContext:
    """只信任本接入域 CA 的服务端 TLS 上下文。"""
    path = Path(cert_dir) / group
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(path / "localhost.crt", path / "localhost.key")
    context.load_verify_locations(path / "ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def build_receiver(domain: str, cert_dir: Path | str, state_path: Path | str,
                   host: str = "127.0.0.1", port: int = 0,
                   trust: Optional[Trust] = None,
                   station: Optional[Station] = None,
                   lock: Optional[threading.Lock] = None) -> tuple[ReceiverServer, ssl.SSLContext]:
    """构造某接入域的接收端。

    可传入共享的 station 与 lock，使两个接入域在同一进程内共享收件事实；
    否则按 state_path 独立装载。
    """
    cert_dir = Path(cert_dir)
    state_path = Path(state_path)
    trust = trust or FileTrust(cert_dir)
    if station is None:
        if state_path.exists():
            station = Station.load(state_path, trust=trust)
        else:
            station = Station(trust=trust)
            station.save(state_path)
    httpd = ReceiverServer(
        (host, port), make_handler(domain), domain, station, state_path,
        lock or threading.Lock(),
    )
    context = server_ssl_context(cert_dir, domain)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd, context


def build_pair(cert_dir: Path | str, state_path: Path | str,
               host: str = "127.0.0.1",
               practice_port: int = 0, race_port: int = 0
               ) -> dict[str, ReceiverServer]:
    """同一站点状态上构建 practice 与 race 两个接收域。"""
    cert_dir = Path(cert_dir)
    state_path = Path(state_path)
    trust = FileTrust(cert_dir)
    if state_path.exists():
        station = Station.load(state_path, trust=trust)
    else:
        station = Station(trust=trust)
        station.save(state_path)
    shared_lock = threading.Lock()
    servers: dict[str, ReceiverServer] = {}
    for domain, port in (("practice", practice_port), ("race", race_port)):
        httpd, _ = build_receiver(
            domain=domain, cert_dir=cert_dir, state_path=state_path,
            host=host, port=port, trust=trust,
            station=station, lock=shared_lock,
        )
        servers[domain] = httpd
    return servers
