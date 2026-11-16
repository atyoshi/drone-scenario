#!/usr/bin/env python3
"""Create a local CORE session, drive fixed lab fixtures, and report acceptance."""

import argparse
import json
import os
import re
import secrets
import shlex
import subprocess
import tempfile
import time
from contextlib import contextmanager
from itertools import pairwise
from pathlib import Path

from common import (
    BLOCK_SECONDS,
    DECOY_SECONDS,
    DRONES,
    IPS_SID,
    OUT_OF_RANGE,
    START_POSITIONS,
    TEST_CLIENT,
    WAN_ADDRESS,
    event,
)

APP = Path("/opt/drone-doctor")
STATE = Path("/run/drone")
CASES = ("firewall", "decoy", "mixed", "pressure")
ROUTER = f"""
table inet lab_router {{
    chain forward {{
        type filter hook forward priority 0; policy drop;
        iifname "outside0" oifname "inside0" ip saddr {TEST_CLIENT} ip daddr {WAN_ADDRESS} tcp dport 80 accept
        iifname "inside0" oifname "outside0" ip saddr {WAN_ADDRESS} ip daddr {TEST_CLIENT} tcp sport 80 ct state established accept
    }}
}}
"""


def command(*args, stdin=None, check=True, timeout=25):
    process = subprocess.run(
        args, input=stdin, text=True, capture_output=True, timeout=timeout, check=False
    )
    if check and process.returncode:
        raise RuntimeError(
            f"{shlex.join(args[:4])}: {process.stderr.strip() or process.stdout.strip()}"
        )
    return process


def docker(*args, **kwargs):
    return command("docker", *args, **kwargs).stdout


def wait_for(predicate, timeout, description):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.16)
    raise RuntimeError(f"timed out waiting for {description}")


def make_credentials(directory):
    ca_key, ca_cert = directory / "ca.key", directory / "ca.crt"
    command(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-noenc",
        "-days",
        "2",
        "-subj",
        "/CN=CORE Drone Doctor lab CA",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_cert),
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign",
    )
    for name, address in DRONES.items():
        target = directory / name
        target.mkdir(mode=0o700)
        key, csr, certificate = (
            target / file for file in ("node.key", "node.csr", "node.crt")
        )
        extensions = target / "extensions"
        extensions.write_text(
            f"basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\n"
            f"keyUsage=critical,digitalSignature\nsubjectAltName=IP:{address}\n"
        )
        command(
            "openssl",
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-noenc",
            "-subj",
            f"/CN={name}",
            "-keyout",
            str(key),
            "-out",
            str(csr),
        )
        command(
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-set_serial",
            str(secrets.randbits(120) + 1),
            "-days",
            "2",
            "-extfile",
            str(extensions),
            "-out",
            str(certificate),
        )
        csr.unlink()
        extensions.unlink()
        (target / "ca.crt").write_bytes(ca_cert.read_bytes())
    bad = directory / "bad-client"
    bad.mkdir(mode=0o700)
    command(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-noenc",
        "-days",
        "1",
        "-subj",
        "/CN=drone-2",
        "-keyout",
        str(bad / "node.key"),
        "-out",
        str(bad / "node.crt"),
    )


class Lab:
    def __init__(self, core, wrappers, args, mode, case, directory):
        self.core, self.wrappers, self.args = core, wrappers, args
        self.mode, self.case, self.directory = mode, case, directory
        self.id = None
        token = secrets.token_hex(4)
        self.names = {
            role: f"dd-{token}-{role}" for role in (*DRONES, "router", "client")
        }
        self.nodes = {}
        self.timeline = []
        self.crash_window = self.link_window = None
        self.benign_window = None
        self.acceptance_start = None
        self.acceptance_end = None

    def node(self, role, *args, **kwargs):
        return docker("exec", "-i", self.names[role], *args, **kwargs)

    def node_json(self, role, *args):
        return json.loads(self.node(role, *args))

    def note(self, kind, **fields):
        entry = event(kind, **fields)
        self.timeline.append(entry)
        print(json.dumps({"mode": self.mode, "case": self.case, **entry}), flush=True)

    def check(self, label, passed, **fields):
        self.note("check", name=label, passed=bool(passed), **fields)

    def define(self):
        Session, NodeType, Position, Interface = (
            self.wrappers.Session,
            self.wrappers.NodeType,
            self.wrappers.Position,
            self.wrappers.Interface,
        )
        self.id = self.core.create_session().id
        session = Session(id=self.id)
        for index, (role, position) in enumerate(
            zip(DRONES, START_POSITIONS, strict=True), 1
        ):
            self.nodes[role] = session.add_node(
                index,
                name=self.names[role],
                _type=NodeType.DOCKER,
                image=self.args.image,
                position=Position(*position),
            )
        self.nodes["router"] = session.add_node(
            5,
            name=self.names["router"],
            _type=NodeType.DOCKER,
            image=self.args.image,
            position=Position(220, 60),
        )
        self.nodes["client"] = session.add_node(
            6,
            name=self.names["client"],
            _type=NodeType.DOCKER,
            image=self.args.image,
            position=Position(105, 60),
        )
        wlan = session.add_node(
            7,
            name="mission-wlan",
            _type=NodeType.WIRELESS_LAN,
            position=Position(270, 190),
        )
        option, kind = self.wrappers.ConfigOption, self.wrappers.ConfigOptionType
        wlan.wlan_config = {
            key: option(
                name=key, value=value, type=kind.FLOAT if key == "error" else kind.INT32
            )
            for key, value in {
                "range": "180",
                "bandwidth": "54000000",
                "delay": "2000",
                "jitter": "0",
                "error": "0",
            }.items()
        }
        for role, address in DRONES.items():
            session.add_link(
                node1=self.nodes[role],
                node2=wlan,
                iface1=Interface(id=0, name="mission0", ip4=address, ip4_mask=24),
            )
        session.add_link(
            node1=self.nodes["client"],
            node2=self.nodes["router"],
            iface1=Interface(id=0, name="outside0", ip4=TEST_CLIENT, ip4_mask=30),
            iface2=Interface(id=0, name="outside0", ip4="198.51.100.1", ip4_mask=30),
        )
        session.add_link(
            node1=self.nodes["router"],
            node2=self.nodes["drone-1"],
            iface1=Interface(id=1, name="inside0", ip4="192.0.2.1", ip4_mask=30),
            iface2=Interface(id=1, name="wan0", ip4=WAN_ADDRESS, ip4_mask=30),
        )
        ok, errors = self.core.start_session(session)
        if not ok or errors:
            raise RuntimeError("CORE session start: " + "; ".join(errors))
        self.note("session_started", session_id=self.id, nodes=self.names)

    def position(self, role, coordinates, move=False):
        x, y = coordinates
        if move and not self.core.move_node(
            self.id, self.nodes[role].id, self.wrappers.Position(x=x, y=y)
        ):
            raise RuntimeError(f"CORE could not move {role}")
        self.node(
            role,
            "sh",
            "-c",
            "cat > /run/drone/position.next && mv /run/drone/position.next /run/drone/position.json",
            stdin=json.dumps(
                {"x": x, "y": y, "unit": "CORE canvas", "sample_ts": time.time()}
            ),
        )
        if move:
            self.note("position_changed", drone=role, x=x, y=y)

    def configure(self):
        self.node("router", "nft", "-f", "-", stdin=ROUTER)
        self.node("router", "sysctl", "-w", "net.ipv4.ip_forward=1")
        self.node(
            "client",
            "ip",
            "route",
            "replace",
            f"{WAN_ADDRESS}/32",
            "via",
            "198.51.100.1",
        )
        self.node(
            "drone-1", "ip", "route", "replace", f"{TEST_CLIENT}/32", "via", "192.0.2.1"
        )
        for role, coordinates in zip(DRONES, START_POSITIONS, strict=True):
            docker(
                "update",
                "--cpus",
                "2",
                "--memory",
                "2g",
                "--memory-swap",
                "2g",
                self.names[role],
            )
            self.node(role, "install", "-d", "-m", "0755", str(STATE))
            docker(
                "cp", str(self.directory / role), f"{self.names[role]}:{STATE}/identity"
            )
            self.position(role, coordinates)
        docker(
            "cp",
            str(self.directory / "bad-client"),
            f"{self.names['drone-2']}:{STATE}/bad-client",
        )
        if self.mode == "model":
            self.node("drone-1", "install", "-d", "-m", "0755", f"{STATE}/model")
            docker(
                "cp",
                str(self.args.llama_dir) + "/.",
                f"{self.names['drone-1']}:{STATE}/model",
                timeout=120,
            )
            docker(
                "cp",
                str(self.args.model_file),
                f"{self.names['drone-1']}:{STATE}/model/model.gguf",
                timeout=120,
            )
            self.node("drone-1", "chmod", "0644", f"{STATE}/model/model.gguf")
            self.node("drone-1", "chmod", "0755", f"{STATE}/model/llama-server")
        for role in DRONES:
            flags = ["--decoy"] if role == "drone-1" and self.case != "firewall" else []
            if role == "drone-1" and self.mode == "model":
                flags.append("--model")
            guard = shlex.join(
                ["python3", str(APP / "guard.py"), "--drone", role, *flags]
            )
            docker(
                "exec",
                "-d",
                self.names[role],
                "sh",
                "-c",
                f"exec {guard} > /run/drone/guard.log 2>&1",
            )
        wait_for(self.all_healthy, 18, "all four agents and authenticated peer links")
        if self.mode == "model":
            wait_for(self.model_ready, 30, "local llama.cpp model")
            self.check("offline model endpoint ready", True)
        self.acceptance_start = time.time()

    def model_ready(self):
        code = (
            "import urllib.request; urllib.request.urlopen("
            "'http://127.0.0.1:8088/health',timeout=0.5).read()"
        )
        result = command(
            "docker", "exec", self.names["drone-1"], "python3", "-c", code, check=False
        )
        return result.returncode == 0

    def status(self, role):
        result = self.node(role, "cat", f"{STATE}/state/status.json", check=False)
        return json.loads(result) if result else {}

    def all_healthy(self):
        for role in DRONES:
            status = self.status(role)
            if (
                status.get("service_health") != "healthy"
                or len(status.get("peers", {})) != 3
                or any(peer["stale"] for peer in status["peers"].values())
            ):
                return False
        return True

    def fixture(self, role, name):
        return self.node_json(role, "python3", str(APP / "fixture.py"), name)

    def events(self, role, file="state/events.jsonl"):
        output = self.node(role, "cat", f"{STATE}/{file}", check=False)
        events = []
        for line in output.splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
        return events

    def seek_event(
        self, role, kind, after, timeout=8, file="state/events.jsonl", **matches
    ):
        def matching():
            return next(
                (
                    row
                    for row in self.events(role, file)
                    if row["kind"] == kind
                    and row["ts"] >= after
                    and all(row.get(key) == value for key, value in matches.items())
                ),
                None,
            )

        return wait_for(matching, timeout, kind)

    def trigger(self):
        since = time.time()
        for _ in range(3):
            self.fixture("client", "probe")
        return self.seek_event("drone-1", "decision", since)

    def counter(self):
        data = self.node_json(
            "drone-1",
            "nft",
            "-j",
            "list",
            "counter",
            "inet",
            "drone_doctor",
            "blocked_hits",
        )
        return next(
            item["counter"]["packets"] for item in data["nftables"] if "counter" in item
        )

    def block_checks(self, decision, expiry):
        self.check(
            "repeated attempts selected temporary firewall block",
            decision["action"] == "block_80" and decision["result"]["ok"],
        )
        if decision["action"] != "block_80" or not decision["result"]["ok"]:
            return
        before = self.counter()
        self.fixture("client", "probe")
        self.check(
            "temporary block counted a subsequent packet", self.counter() > before
        )
        if expiry:
            self.seek_event(
                "drone-1",
                "block_expired",
                decision["ts"] - 0.5,
                BLOCK_SECONDS + 4,
                "guard.log",
            )
            after = self.counter()
            self.fixture("client", "probe")
            self.check("temporary block expired", self.counter() == after)

    def kill_service(self, service):
        pid = self.node_json("drone-1", "cat", f"{STATE}/{service}-pid.json")
        self.node("drone-1", "kill", "-KILL", str(pid))

    def crash_start(self):
        self.crash_window = [time.time(), None]
        self.kill_service("mission")

    def crash_finish(self):
        since = self.crash_window[0]
        recovered = self.seek_event("drone-1", "https_recovered", since, timeout=12)
        self.crash_window[1] = recovered["ts"]
        elapsed = round(recovered["ts"] - since, 3)
        self.check(
            "local mission service recovered within ten seconds",
            elapsed <= 10,
            seconds=elapsed,
        )

    def mobility(self):
        self.link_window = [time.time(), None]
        self.position("drone-4", OUT_OF_RANGE, move=True)
        time.sleep(8)
        stale = all(
            self.status(name)["peers"]["drone-4"]["stale"] for name in list(DRONES)[:3]
        )
        still_local = self.status("drone-4")["service_health"] == "healthy"
        self.check(
            "separated peer marked stale and local service stayed healthy",
            stale and still_local,
        )
        self.position("drone-4", START_POSITIONS[-1], move=True)
        returned = time.monotonic()
        self.link_window[1] = time.time()
        wait_for(self.all_healthy, 3, "fresh peers following reconnection")
        self.check(
            "peer state fresh within three seconds of reconnection",
            time.monotonic() - returned <= 3,
            seconds=round(time.monotonic() - returned, 3),
        )

    def decoy_checks(self, decision):
        active = decision["action"] == "start_decoy" and decision["result"]["ok"]
        self.check("repeated attempts selected inspected decoy", active)
        self.check(
            "ordinary HTTP receives decoy response",
            self.fixture("client", "probe") == {"response": 200, "body": "Lab decoy\n"},
        )
        marker = self.fixture("client", "marker")

        def blocked_marker():
            for line in self.node(
                "drone-1", "cat", f"{STATE}/inline/eve.json"
            ).splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if row.get("alert", {}).get("signature_id") == IPS_SID:
                    return row["alert"].get("action") == "blocked"
            return False

        self.check(
            "inline IPS dropped the harmless marker",
            active
            and marker["response"] is None
            and wait_for(blocked_marker, 3, "IPS drop evidence"),
        )
        if active:
            self.seek_event(
                "drone-1",
                "decoy_closed",
                decision["ts"],
                DECOY_SECONDS + 4,
                "guard.log",
                reason="expired",
            )
        else:
            time.sleep(max(0, decision["ts"] + DECOY_SECONDS - time.time()))
        self.check(
            "decoy lease expired and port closed",
            self.fixture("client", "probe")["response"] is None and active,
        )
        # The previous verification probe counts as an attempt. Wait for its evidence to expire.
        time.sleep(10.1)
        second = self.trigger()
        if second["action"] == "start_decoy" and second["result"]["ok"]:
            self.kill_service("ips")
            self.seek_event(
                "drone-1",
                "decoy_closed",
                second["ts"],
                4,
                "guard.log",
                reason="process_unhealthy",
            )
            self.check(
                "loss of inline IPS closed port 80",
                self.fixture("client", "probe")["response"] is None,
            )
        else:
            self.check("could rearm decoy to test IPS fault", False)

    def exercise(self):
        self.check(
            "external HTTPS unreachable",
            not self.fixture("client", "external-https")["connected"],
        )
        self.check(
            "untrusted TLS client certificate rejected",
            self.fixture("drone-2", "bad-client-cert")["rejected"],
        )
        if self.case == "firewall":
            since = time.time()
            self.fixture("client", "single")
            self.seek_event("drone-1", "port80_observed", since)
            recent = [
                row
                for row in self.events("drone-1")
                if row["ts"] >= since and row["kind"] in {"decision", "port80_observed"}
            ]
            self.check(
                "isolated attempt and retransmissions yielded one observation",
                len(recent) == 1
                and recent[0]["kind"] == "port80_observed"
                and recent[0]["window_attempts"] == 1,
            )
            time.sleep(10.1)
            self.benign_window = (since, time.time())
            self.block_checks(self.trigger(), expiry=True)
            self.crash_start()
            self.crash_finish()
            self.mobility()
        elif self.case == "decoy":
            self.decoy_checks(self.trigger())
        elif self.case == "pressure":
            self.node("drone-1", "touch", f"{STATE}/pressure")
            self.block_checks(self.trigger(), expiry=False)
        elif self.case == "mixed":
            # Cause two probes first, then align the third with the first failed health sample.
            since = time.time()
            for _ in range(2):
                self.fixture("client", "probe")
            self.crash_start()
            self.seek_event("drone-1", "https_failed", self.crash_window[0], timeout=3)
            self.fixture("client", "probe")
            decision = self.seek_event("drone-1", "decision", since)
            self.block_checks(decision, expiry=False)
            self.crash_finish()
        self.acceptance_end = time.time()
        self.check_mission_ticks()

    def check_mission_ticks(self):
        samples = failures = 0
        sampled_drones = set()
        for role in DRONES:
            for row in self.events(role):
                stamp = row["ts"]
                if (
                    row["kind"] != "health_tick"
                    or not self.acceptance_start <= stamp <= self.acceptance_end
                ):
                    continue
                checks = {**row["peers_ok"], role: row["local_ok"]}
                for target, okay in checks.items():
                    crash = (
                        self.crash_window
                        and target == "drone-1"
                        and (self.crash_window[0] <= stamp <= self.crash_window[1] + 1)
                    )
                    separation = (
                        self.link_window
                        and role != target
                        and "drone-4" in (role, target)
                        and (self.link_window[0] <= stamp <= self.link_window[1] + 1)
                    )
                    if crash or separation:
                        continue
                    samples += 1
                    sampled_drones.add(role)
                    failures += not okay
        self.check(
            "mission HTTPS stayed available outside injected faults",
            sampled_drones == set(DRONES) and failures == 0,
            checks=samples,
            failures=failures,
        )

    def collect(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        combined = list(self.timeline)
        for role in DRONES:
            for file in ("state/events.jsonl.1", "state/events.jsonl", "guard.log"):
                combined.extend(
                    {"drone": role, **row}
                    for row in self.events(role, file)
                    if isinstance(row, dict) and "ts" in row
                )
            guard_log = self.node(role, "cat", f"{STATE}/guard.log", check=False)
            (self.directory / f"{role}-guard.log").write_text(guard_log)
        combined.sort(key=lambda row: row["ts"])
        (self.directory / "timeline.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in combined)
        )
        for name in (
            "sensor/eve.json",
            "inline/eve.json",
            "sensor/suricata.log",
            "inline/suricata.log",
            "model.log",
        ):
            log = self.node("drone-1", "cat", f"{STATE}/{name}", check=False)
            (self.directory / name.replace("/", "-")).write_text(log)
        return combined

    def run(self):
        passed = False
        summary = {}
        with tempfile.TemporaryDirectory(prefix="drone-doctor-credentials-") as private:
            result_dir = self.directory
            self.directory = Path(private)
            try:
                make_credentials(self.directory)
                self.define()
                self.configure()
                self.exercise()
                passed = all(
                    row["passed"] for row in self.timeline if row["kind"] == "check"
                )
            except (
                RuntimeError,
                OSError,
                ValueError,
                subprocess.SubprocessError,
            ) as error:
                self.note("run_error", error=str(error))
            finally:
                self.directory = result_dir
                try:
                    rows = self.collect()
                    decisions = [row for row in rows if row["kind"] == "decision"]
                    expected = "start_decoy" if self.case == "decoy" else "block_80"
                    summary = {
                        "checks": [
                            row for row in self.timeline if row["kind"] == "check"
                        ],
                        "decisions": len(decisions),
                        "correct_actions": sum(
                            row["action"] == expected and row["result"]["ok"]
                            for row in decisions
                        ),
                        "model_fallbacks": sum(
                            self.mode == "model"
                            and row["selector"].startswith("rules_fallback")
                            for row in decisions
                        ),
                        "false_blocks": (
                            sum(
                                row["action"] == "block_80"
                                and row["result"]["ok"]
                                and self.benign_window[0]
                                <= row["ts"]
                                < self.benign_window[1]
                                for row in decisions
                            )
                            if self.benign_window
                            else None
                        ),
                    }
                    resources = self.fixture("drone-1", "resources")
                    summary["peak_memory_bytes"] = resources["memory_peak_bytes"]
                    ticks = [
                        row
                        for row in rows
                        if row["kind"] == "health_tick"
                        and row.get("drone") == "drone-1"
                        and "cpu_usec" in row
                    ]
                    summary["peak_cpu_cores_sampled"] = max(
                        (
                            (right["cpu_usec"] - left["cpu_usec"])
                            / (1e6 * (right["ts"] - left["ts"]))
                            for left, right in pairwise(ticks)
                            if right["ts"] > left["ts"]
                        ),
                        default=None,
                    )
                except (
                    RuntimeError,
                    OSError,
                    ValueError,
                    subprocess.SubprocessError,
                ) as error:
                    passed = False
                    self.note("collection_error", error=str(error))
                if self.id is not None:
                    try:
                        if self.args.keep:
                            self.note("session_retained", session_id=self.id)
                        elif not self.core.delete_session(self.id):
                            raise RuntimeError("CORE did not confirm deletion")
                    except Exception as error:  # noqa: BLE001 - CORE can raise version-specific RPC errors
                        passed = False
                        self.note("cleanup_error", error=str(error), session_id=self.id)
        return {"mode": self.mode, "case": self.case, "passed": passed, **summary}


def preflight(args):
    errors = []
    core = wrappers = None
    try:
        import grpc
        from core.api.grpc import client, wrappers

        core = client.CoreGrpcClient(f"127.0.0.1:{args.core_port}")
        core.connect()
        grpc.channel_ready_future(core.channel).result(timeout=3)
    except Exception as error:  # noqa: BLE001 - report dependency, channel, and RPC failures together
        errors.append(
            f"CORE gRPC at localhost:{args.core_port}: {type(error).__name__} {error}"
        )
    try:
        docker("version", "--format", "{{.Server.Version}}")
        docker("image", "inspect", args.image)
        print(
            docker(
                "run",
                "--rm",
                "--network",
                "none",
                "--cap-add",
                "NET_ADMIN",
                "--cpus",
                "2",
                "--memory",
                "2g",
                "--memory-swap",
                "2g",
                args.image,
                "python3",
                str(APP / "fixture.py"),
                "preflight",
            ).strip()
        )
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        errors.append(str(error))
    if errors:
        if core:
            core.close()
        raise RuntimeError("\n".join(errors))
    return core, wrappers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="drone-doctor:lab")
    parser.add_argument("--core-port", type=int, default=50051)
    parser.add_argument("--results", type=Path, default=Path("runs"))
    parser.add_argument("--case", choices=[*CASES, "all"], default="all")
    parser.add_argument(
        "--mode", choices=["rules", "model", "compare"], default="rules"
    )
    parser.add_argument("--llama-dir", type=Path)
    parser.add_argument("--model-file", type=Path)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument(
        "--keep", action="store_true", help="leave session(s) visible in the CORE GUI"
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]*", args.image):
        parser.error("invalid Docker image reference")
    if not 1 <= args.core_port <= 65535:
        parser.error("invalid CORE gRPC port")
    if args.mode != "rules" and not args.preflight:
        if not (
            args.llama_dir
            and args.model_file
            and args.model_file.is_file()
            and os.access(args.llama_dir / "llama-server", os.X_OK)
        ):
            parser.error(
                "model modes require a local --llama-dir with llama-server and a --model-file"
            )
        args.llama_dir = args.llama_dir.resolve()
        args.model_file = args.model_file.resolve()
    try:
        core, wrappers = preflight(args)
    except RuntimeError as error:
        parser.exit(2, f"Lab preflight failed\n{error}\n")
    with _connected(core):
        if args.preflight:
            print("CORE, Docker, nftables and NFQUEUE preflight passed")
            return 0
        parent = args.results / (
            time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        )
        parent.mkdir(parents=True)
        modes = ("rules", "model") if args.mode == "compare" else (args.mode,)
        cases = CASES if args.case == "all" else (args.case,)
        reports = [
            Lab(core, wrappers, args, mode, case, parent / f"{mode}-{case}").run()
            for mode in modes
            for case in cases
        ]
        (parent / "summary.json").write_text(json.dumps(reports, indent=2) + "\n")
        print(f"Report saved to {parent / 'summary.json'}")
        return 0 if all(report["passed"] for report in reports) else 1


@contextmanager
def _connected(core):
    try:
        yield
    finally:
        core.close()


if __name__ == "__main__":
    raise SystemExit(main())
