"""生成仅用于本地演练的证书，不保存共享私钥。"""
import argparse
import json
from pathlib import Path
import subprocess


def openssl(directory, *args):
    result = subprocess.run(["openssl", *args], cwd=directory, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"生成演练证书失败\n{result.stderr}")


def build_group(directory, group, clients):
    folder = directory / group
    folder.mkdir(parents=True)
    openssl(folder, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-x509", "-days", "30",
            "-keyout", "ca.key", "-out", "ca.crt", "-subj", f"/CN=local-{group}-ca",
            "-addext", "basicConstraints=critical,CA:TRUE")
    client_ext = folder / "client.ext"
    server_ext = folder / "server.ext"
    client_ext.write_text("basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth,emailProtection\n",
                          encoding="utf-8")
    server_ext.write_text("basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
                          encoding="utf-8")
    for label in ["localhost", *clients]:
        ext = server_ext.name if label == "localhost" else client_ext.name
        openssl(folder, "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", f"/CN={label}", "-out", f"{label}.csr", "-keyout", f"{label}.key")
        openssl(folder, "x509", "-req", "-in", f"{label}.csr", "-CA", "ca.crt", "-CAkey",
                "ca.key", "-CAcreateserial", "-days", "7", "-sha256", "-extfile", ext,
                "-out", f"{label}.crt")
        (folder / f"{label}.csr").unlink()
    for intermediate in ("ca.key", "ca.srl", client_ext.name, server_ext.name):
        (folder / intermediate).unlink()
    # 信任清单：该接入域信任根下可用的真实 TLS 客户端身份
    manifest = {
        "domain": group,
        "ca": "ca.crt",
        "client_labels": list(clients),
        "server_label": "localhost",
    }
    (folder / "trust.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser(description="为本机编辑端或计时端生成演练证书")
    parser.add_argument("--output", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--editorial", action="store_true")
    group.add_argument("--timing", action="store_true")
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    if options.editorial:
        build_group(options.output, "editorial", ["desk-h", "desk-w", "desk-j", "desk-p"])
    else:
        build_group(options.output, "practice", ["timer-p1"])
        build_group(options.output, "race", ["timer-r1", "timer-r2", "timer-r3"])


if __name__ == "__main__":
    main()
