"""Local supervisor and narrowly scoped firewall/IPS helper."""

import argparse
import fcntl
import grp
import json
import os
import pwd
import select
import socket
import struct
import subprocess
import time
from pathlib import Path

from common import (
    BLOCK_SECONDS,
    CONTROL,
    DECOY_SECONDS,
    DRONES,
    IDENTITY,
    RUN,
    STATUS,
    TEST_CLIENT,
    WAN_ADDRESS,
    WAN_IFACE,
    atomic_json,
    cgroup_cpu_usec,
    event,
)

APP = Path(__file__).resolve().parent
DOCTOR_UID = 18081
RESERVE = 512 * 1024**2
TABLE = "table inet drone_doctor"
QUEUE = 7
LOG_LIMIT = ["prlimit", "--fsize=16777216:16777216", "--"]


def nft(script):
    return subprocess.run(
        ["nft", "-f", "-"],
        input=script,
        text=True,
        check=True,
        capture_output=True,
        timeout=2,
    )


def nft_json(*command):
    result = subprocess.run(
        ["nft", "-j", *command], check=True, capture_output=True, text=True, timeout=2
    )
    return json.loads(result.stdout)


def firewall():
    return f"""
{TABLE} {{
    set blocked {{ type ipv4_addr; flags timeout; size 1; }}
    set inspected {{ type ipv4_addr; flags timeout; size 1; }}
    counter blocked_hits {{ }}
    counter default_drops {{ }}
    chain input {{
        type filter hook input priority 0; policy accept;
        iifname "{WAN_IFACE}" ip saddr {TEST_CLIENT} ip daddr {WAN_ADDRESS} tcp dport 80 jump external_http
        iifname "{WAN_IFACE}" drop
    }}
    chain external_http {{
        ip saddr @blocked counter name blocked_hits drop
        ip saddr @inspected limit rate 20/second burst 32 packets queue num {QUEUE}
        counter name default_drops drop
    }}
    chain output {{
        type filter hook output priority 0; policy accept;
        oifname "{WAN_IFACE}" ip saddr {WAN_ADDRESS} ip daddr @inspected tcp sport 80 ct state established queue num {QUEUE}
        meta skuid 18083 drop
        oifname "{WAN_IFACE}" drop
    }}
    chain forward {{
        type filter hook forward priority 0; policy accept;
        iifname "{WAN_IFACE}" drop
        oifname "{WAN_IFACE}" drop
    }}
}}
"""


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=0.6)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def alive(process):
    return process is not None and process.poll() is None


def run_as(user):
    return [
        "setpriv",
        "--reuid",
        user,
        "--regid",
        str(pwd.getpwnam(user).pw_gid),
        "--init-groups",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
    ]


def resource_snapshot():
    cgroup = Path("/sys/fs/cgroup")
    memory = int((cgroup / "memory.current").read_text())
    limit_text = (cgroup / "memory.max").read_text().strip()
    maximum = None if limit_text == "max" else int(limit_text)
    return {
        "ok": maximum is not None
        and maximum - memory >= RESERVE
        and not (RUN / "pressure").exists(),
        "memory_bytes": memory,
        "memory_limit_bytes": maximum,
        "cpu_usec": cgroup_cpu_usec(),
    }


def has_queue():
    try:
        lines = Path("/proc/net/netfilter/nfnetlink_queue").read_text().splitlines()
        return any(line.split() and int(line.split()[0]) == QUEUE for line in lines)
    except OSError:
        return False


class Guard:
    def __init__(self, args):
        self.args = args
        self.mission = self.sensor = self.ips = self.decoy = self.model = (
            self.doctor
        ) = None
        self.mode = "default"
        self.expiry = 0
        self.owns_firewall = False
        self.lock = None
        self.owns_socket = False

    def log(self, kind, **fields):
        print(json.dumps(event(kind, **fields)), flush=True)

    def prepare(self):
        links = json.loads(
            subprocess.check_output(["ip", "-j", "-4", "addr"], text=True)
        )
        addresses = {
            item["ifname"]: {address["local"] for address in item.get("addr_info", [])}
            for item in links
        }
        expected = {"lo", "mission0"}
        if self.args.drone == "drone-1":
            expected.add(WAN_IFACE)
        if (
            set(addresses) != expected
            or DRONES[self.args.drone] not in addresses["mission0"]
            or (WAN_IFACE in expected and WAN_ADDRESS not in addresses[WAN_IFACE])
        ):
            raise RuntimeError("guard requires the isolated CORE drone namespace")
        RUN.chmod(0o755)
        lock = (RUN / "guard.lock").open("a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            lock.close()
            raise
        self.lock = lock
        for folder in ("state", "sensor", "inline"):
            (RUN / folder).mkdir(exist_ok=True)
        os.chown(STATUS.parent, DOCTOR_UID, grp.getgrnam("missionauth").gr_gid)
        IDENTITY.chmod(0o750)
        os.chown(IDENTITY, 0, grp.getgrnam("missionauth").gr_gid)
        os.chown(IDENTITY / "node.key", 0, grp.getgrnam("missionauth").gr_gid)
        (IDENTITY / "node.key").chmod(0o640)
        for folder in ("sensor", "inline"):
            (RUN / folder / "eve.json").touch(mode=0o644)
        if self.args.drone == "drone-1":
            Path("/proc/sys/net/ipv4/ip_forward").write_text("0\n")
            Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").write_text("80\n")
            exists = any(
                item.get("table", {}).get("name") == "drone_doctor"
                and item["table"]["family"] == "inet"
                for item in nft_json("list", "tables")["nftables"]
            )
            nft((f"delete {TABLE}\n" if exists else "") + firewall())
            self.owns_firewall = True
            self.sensor = self.start_suricata(False)
        self.restart_mission()
        if self.args.model:
            model_dir = RUN / "model"
            with (RUN / "model.log").open("ab") as log:
                self.model = subprocess.Popen(
                    [
                        *LOG_LIMIT,
                        *run_as("inference"),
                        str(model_dir / "llama-server"),
                        "--host",
                        "127.0.0.1",
                        "--port",
                        "8088",
                        "-m",
                        str(model_dir / "model.gguf"),
                        "--alias",
                        "local",
                        "--threads",
                        "2",
                        "--ctx-size",
                        "1024",
                        "--parallel",
                        "1",
                    ],
                    env={**os.environ, "LD_LIBRARY_PATH": str(model_dir)},
                    stdout=log,
                    stderr=log,
                )

    def restart_mission(self):
        stop(self.mission)
        self.mission = subprocess.Popen(
            [
                *run_as("mission"),
                "python3",
                str(APP / "services.py"),
                "mission",
                "--drone",
                self.args.drone,
            ],
            stdout=subprocess.DEVNULL,
        )
        atomic_json(RUN / "mission-pid.json", self.mission.pid)

    def start_suricata(self, inline):
        folder = RUN / ("inline" if inline else "sensor")
        mode = ["-q", str(QUEUE)] if inline else [f"--af-packet={WAN_IFACE}"]
        with (folder / "suricata.log").open("ab") as log:
            process = subprocess.Popen(
                [
                    *LOG_LIMIT,
                    "suricata",
                    "-c",
                    str(APP / "suricata.yaml"),
                    "-l",
                    str(folder),
                    "-S",
                    str(APP / ("inline.rules" if inline else "observe.rules")),
                    *mode,
                ],
                stdout=log,
                stderr=log,
            )
        if inline:
            atomic_json(RUN / "ips-pid.json", process.pid)
        return process

    def close_decoy(self, reason):
        try:
            nft("flush set inet drone_doctor inspected")
        finally:
            stop(self.decoy)
            stop(self.ips)
            self.decoy = self.ips = None
            self.mode = "default"
            self.expiry = 0
        self.log("decoy_closed", reason=reason, verified=True)

    def start_decoy(self):
        if (
            self.mode != "default"
            or not self.args.decoy
            or not alive(self.sensor)
            or not alive(self.mission)
            or not resource_snapshot()["ok"]
        ):
            return {"ok": False, "reason": "decoy prerequisites unavailable"}
        try:
            self.ips = self.start_suricata(True)
            deadline = time.monotonic() + 2
            while not has_queue() and alive(self.ips) and time.monotonic() < deadline:
                time.sleep(0.05)
            if not alive(self.ips) or not has_queue():
                raise RuntimeError("NFQUEUE listener did not become ready")
            self.decoy = subprocess.Popen(
                [*run_as("decoy"), "python3", str(APP / "services.py"), "decoy"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            with self.decoy.stdout as ready:
                if (
                    not select.select([ready], [], [], 1)[0]
                    or ready.readline() != b"ready\n"
                ):
                    raise RuntimeError("decoy listener did not become ready")
            if (
                not alive(self.ips)
                or not alive(self.decoy)
                or not resource_snapshot()["ok"]
            ):
                raise RuntimeError("decoy or IPS prerequisites changed during startup")
            nft(
                f"add element inet drone_doctor inspected {{ {TEST_CLIENT} timeout {DECOY_SECONDS}s }}"
            )
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            self.close_decoy(type(error).__name__)
            return {"ok": False, "reason": str(error)}
        self.mode = "decoy"
        self.expiry = time.monotonic() + DECOY_SECONDS
        return {
            "ok": True,
            "ttl_s": DECOY_SECONDS,
            "verified": "IPS and decoy ready, nft lease installed",
        }

    def dispatch(self, request):
        if not isinstance(request, dict) or set(request) != {"action"}:
            return {"ok": False, "reason": "unsupported request shape"}
        action = request["action"]
        if action == "restart_https":
            self.restart_mission()
            return {"ok": True}
        if action == "status":
            return {
                "ok": True,
                "mode": self.mode,
                "sensor_ok": alive(self.sensor),
                "model_ok": alive(self.model),
                "resources": resource_snapshot(),
            }
        if self.args.drone != "drone-1":
            return {"ok": False, "reason": "action unavailable on this drone"}
        if action == "start_decoy":
            return self.start_decoy()
        if action == "stop_decoy" and self.mode == "decoy":
            self.close_decoy("agent_request")
            return {"ok": True}
        if action == "block_80" and self.mode == "default" and alive(self.sensor):
            nft(
                f"add element inet drone_doctor blocked {{ {TEST_CLIENT} timeout {BLOCK_SECONDS}s }}"
            )
            self.mode = "block"
            self.expiry = time.monotonic() + BLOCK_SECONDS
            return {
                "ok": True,
                "ttl_s": BLOCK_SECONDS,
                "verified": "nft lease installed",
            }
        return {"ok": False, "reason": "action unavailable in current state"}

    def maintain(self):
        if self.mode == "block" and time.monotonic() >= self.expiry:
            self.mode = "default"
            self.log("block_expired", verified=True)
        if self.mode == "decoy":
            if time.monotonic() >= self.expiry:
                self.close_decoy("expired")
            elif not all(
                map(
                    alive,
                    (self.ips, self.sensor, self.decoy, self.doctor, self.mission),
                )
            ):
                self.close_decoy("process_unhealthy")
            elif not resource_snapshot()["ok"]:
                self.close_decoy("resource_pressure")

    def serve(self):
        self.prepare()
        CONTROL.unlink(missing_ok=True)
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(CONTROL))
            self.owns_socket = True
            os.chown(CONTROL, DOCTOR_UID, 0)
            CONTROL.chmod(0o600)
            listener.listen(8)
            listener.settimeout(0.15)
            self.doctor = subprocess.Popen(
                [
                    *run_as("doctor"),
                    "python3",
                    str(APP / "doctor.py"),
                    "--drone",
                    self.args.drone,
                    *(["--model"] if self.args.model else []),
                    *(["--decoy"] if self.args.decoy else []),
                ],
            )
            self.log("guard_ready", drone=self.args.drone)
            while alive(self.doctor):
                self.maintain()
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(0.2)
                    try:
                        credentials = connection.getsockopt(
                            socket.SOL_SOCKET, socket.SO_PEERCRED, 12
                        )
                        _, uid, _ = struct.unpack("3i", credentials)
                        if uid != DOCTOR_UID:
                            continue
                        with connection.makefile("rb") as stream:
                            response = self.dispatch(json.loads(stream.readline(1024)))
                        connection.sendall(json.dumps(response).encode() + b"\n")
                    except (OSError, ValueError, subprocess.SubprocessError) as error:
                        self.log("helper_error", error=str(error))

    def shutdown(self):
        for process in (
            self.ips,
            self.decoy,
            self.sensor,
            self.model,
            self.doctor,
            self.mission,
        ):
            stop(process)
        try:
            if self.owns_firewall:
                nft("flush set inet drone_doctor inspected")
        finally:
            if self.owns_socket:
                CONTROL.unlink(missing_ok=True)
            if self.lock is not None:
                self.lock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--drone", required=True, choices=DRONES)
    parser.add_argument("--decoy", action="store_true")
    parser.add_argument("--model", action="store_true")
    guard = Guard(parser.parse_args())
    try:
        guard.serve()
    finally:
        guard.shutdown()


if __name__ == "__main__":
    main()
