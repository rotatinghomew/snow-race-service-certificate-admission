"""读取本地合作方的演练记录。"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
from urllib.parse import parse_qs, urlsplit


DATA = Path(__file__).resolve().parent / "data"


def load(root=DATA):
    """读取来源目录和按观测时间排列的业务来件。"""
    description = json.loads((root / "sources.json").read_text(encoding="utf-8"))
    with (root / "observations.jsonl").open(encoding="utf-8") as stream:
        records = [json.loads(line) for line in stream if line.strip()]
    return description, records


def handler(sources, records):
    class Feed(BaseHTTPRequestHandler):
        def reply(self, status, body):
            encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
            request = urlsplit(self.path)
            if request.path == "/sources":
                self.reply(200, sources)
                return
            if request.path != "/observations":
                self.reply(404, {"message": "未找到资料入口"})
                return
            query = parse_qs(request.query)
            source = query.get("source", [None])[0]
            if source is not None and source not in sources:
                self.reply(404, {"message": "未登记该来源"})
                return
            try:
                cutoff = int(query["through"][0]) if "through" in query else None
            except ValueError:
                self.reply(400, {"message": "观测截止时间应为整数"})
                return
            records_in_range = [
                row for row in records if (source is None or row["source"] == source)
                and (cutoff is None or row["observed"] <= cutoff)
            ]
            self.reply(200, records_in_range)

    return Feed


def serve(host, port, root=DATA, tls_context=None):
    """启动本地只读资料端。"""
    sources, records = load(root)
    server = ThreadingHTTPServer((host, port), handler(sources, records))
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server


def tls_context(cert_dir, group):
    """用指定场馆域的演练证书接入资料端。"""
    path = cert_dir / group
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(path / "localhost.crt", path / "localhost.key")
    context.load_verify_locations(path / "ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def main():
    parser = argparse.ArgumentParser(description="本地合作方资料端")
    parser.add_argument("--port", default=8091, type=int, help="本机监听端口")
    parser.add_argument("--cert-dir", type=Path, help="已生成的本地演练证书目录")
    parser.add_argument("--trust-domain", choices=("practice", "race"), help="需客户端证书的资料渠道")
    args = parser.parse_args()
    if bool(args.cert_dir) != bool(args.trust_domain):
        parser.error("演练证书目录与渠道应一同指定")
    context = tls_context(args.cert_dir, args.trust_domain) if args.cert_dir else None
    with serve("127.0.0.1", args.port, tls_context=context) as server:
        print(f"本地资料端口 {server.server_address[1]}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
