"""Shared lab addresses, credentials, and local I/O."""

import http.client
import json
import socket
import ssl
import time
from pathlib import Path

DRONES = {f"drone-{i}": f"10.42.0.{i}" for i in range(1, 5)}
START_POSITIONS = [(260, 130), (200, 200), (270, 240), (335, 195)]
OUT_OF_RANGE = (650, 195)
TEST_CLIENT = "198.51.100.2"
WAN_ADDRESS = "192.0.2.2"
WAN_IFACE = "wan0"
RUN = Path("/run/drone")
CONTROL = RUN / "control.sock"
IDENTITY = RUN / "identity"
STATUS = RUN / "state" / "status.json"
POSITION = RUN / "position.json"
OBSERVE_SID = 9100001
IPS_SID = 9100002
MARKER_PATH = "/__drone_doctor_ips_test__"
BLOCK_SECONDS = 30
DECOY_SECONDS = 60
MEMORY_LIMIT = 2 * 1024**3


def atomic_json(path, value, mode=0o644):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value) + "\n")
    temporary.chmod(mode)
    temporary.replace(path)


def read_json(path):
    return json.loads(path.read_text())


def client_tls(identity=IDENTITY, authenticated=True):
    context = ssl.create_default_context(cafile=str(identity / "ca.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if authenticated:
        context.load_cert_chain(identity / "node.crt", identity / "node.key")
    return context


def https_status(address, context, path="/status"):
    connection = http.client.HTTPSConnection(address, 443, context=context, timeout=0.7)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"HTTPS status {response.status}")
        body = response.read(8193)
        if len(body) > 8192:
            raise ValueError("status document too large")
        return json.loads(body)
    finally:
        connection.close()


def local_request(action, **arguments):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(6)
        connection.connect(str(CONTROL))
        connection.sendall(json.dumps({"action": action, **arguments}).encode() + b"\n")
        with connection.makefile("rb") as response:
            return json.loads(response.readline(4096))


def event(kind, **fields):
    return {"ts": time.time(), "kind": kind, **fields}


def cgroup_cpu_usec():
    cpu_stats = Path("/sys/fs/cgroup/cpu.stat").read_text().splitlines()
    return int(dict(line.split() for line in cpu_stats)["usage_usec"])
