"""Fixed-endpoint acceptance fixtures. No target or port discovery."""

import argparse
import http.client
import json
import socket
import ssl
import subprocess
import time
from pathlib import Path

from common import (
    DRONES,
    MARKER_PATH,
    MEMORY_LIMIT,
    RUN,
    WAN_ADDRESS,
    client_tls,
    https_status,
)
from guard import APP, firewall, has_queue, nft, resource_snapshot, stop


def probe(path, port, timeout):
    client = http.client.HTTPConnection(WAN_ADDRESS, port, timeout=timeout)
    try:
        client.request("GET", path)
        response = client.getresponse()
        return {"response": response.status, "body": response.read(80).decode("ascii")}
    except (OSError, http.client.HTTPException):
        return {"response": None}
    finally:
        client.close()


def preflight():
    quota, period = (Path("/sys/fs/cgroup") / "cpu.max").read_text().split()
    if (
        resource_snapshot()["memory_limit_bytes"] != MEMORY_LIMIT
        or quota == "max"
        or int(quota) != 2 * int(period)
    ):
        raise RuntimeError(
            "container requires cgroup v2 with two CPUs and 2 GiB RAM enforced"
        )
    info = subprocess.check_output(["suricata", "--build-info"], text=True)
    if not any(
        "NFQueue support:" in line and line.rstrip().endswith("yes")
        for line in info.splitlines()
    ):
        raise RuntimeError("Suricata in the image lacks NFQUEUE support")
    nft(firewall())
    log_dir = Path("/tmp/nfq-preflight")
    log_dir.mkdir(exist_ok=True)
    process = subprocess.Popen(
        [
            "suricata",
            "-c",
            str(APP / "suricata.yaml"),
            "-S",
            str(APP / "inline.rules"),
            "-l",
            str(log_dir),
            "-q",
            "7",
        ],
    )
    try:
        deadline = time.monotonic() + 4
        while process.poll() is None and time.monotonic() < deadline:
            if has_queue():
                return {"nfqueue": True, "nftables": True}
            time.sleep(0.05)
        raise RuntimeError("container could not bind NFQUEUE 7")
    finally:
        stop(process)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "fixture",
        choices=[
            "probe",
            "marker",
            "single",
            "external-https",
            "bad-client-cert",
            "preflight",
            "resources",
        ],
    )
    args = parser.parse_args()
    if args.fixture == "preflight":
        result = preflight()
    elif args.fixture == "resources":
        result = resource_snapshot()
        result["memory_peak_bytes"] = int(
            Path("/sys/fs/cgroup/memory.peak").read_text()
        )
    elif args.fixture == "bad-client-cert":
        context = client_tls(authenticated=False)
        context.load_cert_chain(
            RUN / "bad-client" / "node.crt", RUN / "bad-client" / "node.key"
        )
        try:
            https_status(DRONES["drone-1"], context, "/healthz")
            result = {"rejected": False}
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
            result = {"rejected": True}
    elif args.fixture == "external-https":
        try:
            with socket.create_connection((WAN_ADDRESS, 443), timeout=0.65):
                result = {"connected": True}
        except OSError:
            result = {"connected": False}
    else:
        path = MARKER_PATH if args.fixture == "marker" else "/"
        result = probe(path, 80, 1.5 if args.fixture == "single" else 0.60)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
