"""Unprivileged per-drone monitoring and response loop."""

import argparse
import concurrent.futures
import http.client
import json
import logging
import threading
import time
from collections import deque
from logging.handlers import RotatingFileHandler

from common import (
    DRONES,
    POSITION,
    RUN,
    STATUS,
    atomic_json,
    cgroup_cpu_usec,
    client_tls,
    event,
    https_status,
    local_request,
    read_json,
)
from policy import BLOCK, DECOY, THRESHOLD, Attempts, choices, choose_model


class Peer:
    def __init__(self):
        self.stale = True
        self.missed = self.good = 0
        self.position = None
        self.incident = None
        self.last_success = None

    def update(self, status):
        previous = self.stale
        if status is None:
            self.missed += 1
            self.good = 0
            if self.missed >= 3:
                self.stale = True
        else:
            self.missed = 0
            self.good += 1
            if self.good >= 2:
                self.stale = False
            self.position = status["position"]
            self.incident = status["incident"]
            self.last_success = time.time()
        return self.stale != previous

    def summary(self):
        return {
            "stale": self.stale,
            "position": self.position,
            "incident": self.incident,
            "last_success": self.last_success,
        }


class Doctor:
    def __init__(self, args):
        self.args = args
        self.tls = client_tls()
        self.peers = {name: Peer() for name in DRONES if name != args.drone}
        self.bad_health = self.good_health = 0
        self.health = "starting"
        self.restart_times = deque()
        self.recovering = False
        self.incident = "none"
        self.model_pool = (
            concurrent.futures.ThreadPoolExecutor(max_workers=1) if args.model else None
        )
        self.pending_model = None
        self.log_writer = logging.getLogger(args.drone)
        self.log_writer.setLevel(logging.INFO)
        self.log_writer.propagate = False
        handler = RotatingFileHandler(
            STATUS.parent / "events.jsonl", maxBytes=1024**2, backupCount=1
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.log_writer.addHandler(handler)

    def log(self, kind, **fields):
        self.log_writer.info(json.dumps(event(kind, drone=self.args.drone, **fields)))

    def poll(self, drone, path):
        try:
            status = https_status(DRONES[drone], self.tls, path)
            if status["drone_id"] == drone:
                if path == "/healthz" and status.get("ok") is True:
                    return status
                if (
                    path == "/status"
                    and isinstance(status["position"], dict)
                    and isinstance(status["incident"], str)
                ):
                    return status
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
            pass
        return None

    def update_health(self, status):
        now = time.monotonic()
        if status is not None:
            self.bad_health = 0
            self.good_health += 1
            if self.good_health >= 2 and self.health != "healthy":
                self.health = "healthy"
                self.log(
                    "https_recovered" if self.recovering else "https_healthy",
                    verified=True,
                )
                self.recovering = False
            return
        self.good_health = 0
        self.bad_health += 1
        if self.health != "degraded":
            self.health = "degraded"
            self.log("https_failed")
        if self.bad_health < 2:
            return
        while self.restart_times and self.restart_times[0] <= now - 60:
            self.restart_times.popleft()
        if len(self.restart_times) >= 2:
            return
        self.restart_times.append(now)
        self.bad_health = 0
        self.recovering = True
        try:
            result = local_request("restart_https")
        except (OSError, ValueError) as error:
            result = {"ok": False, "reason": type(error).__name__}
        self.log("https_restart", result=result)

    def publish(self):
        position = read_json(POSITION)
        atomic_json(
            STATUS,
            {
                "drone_id": self.args.drone,
                "mission_phase": "survey",
                "position": position,
                "service_health": self.health,
                "incident": self.incident,
                "peers": {name: peer.summary() for name, peer in self.peers.items()},
            },
        )

    def select_action(self, allowed, attempts, healthy, resources_ok):
        if self.model_pool is None:
            return allowed[0], attempts, "rules"
        if self.pending_model is not None and not self.pending_model.done():
            return allowed[0], attempts, "rules_fallback:model_busy"
        self.pending_model = self.model_pool.submit(
            choose_model, allowed, attempts, "survey", healthy, resources_ok
        )
        try:
            return self.pending_model.result(timeout=2)
        except TimeoutError:
            return allowed[0], attempts, "rules_fallback:model_deadline"

    def apply_policy(self, attempts):
        try:
            helper = local_request("status")
            if not helper["sensor_ok"] or helper["mode"] != "default":
                return
            resources_ok = helper["resources"]["ok"]
            healthy = self.health == "healthy"
            allowed = choices(self.args.decoy, healthy, resources_ok)
            action, ids, selector = self.select_action(
                allowed, attempts, healthy, resources_ok
            )
            if action == DECOY and self.health != "healthy":
                action, ids, selector = BLOCK, attempts, "rules_fallback:health_changed"
            result = local_request(action)
            if action == DECOY and not result["ok"]:
                self.log("decoy_start_failed", evidence_ids=ids, result=result)
                action, ids, selector = (
                    BLOCK,
                    attempts,
                    "rules_fallback:decoy_unavailable",
                )
                result = local_request(action)
            self.incident = action if result["ok"] else "action_failed"
            self.log(
                "decision",
                action=action,
                evidence_ids=ids,
                selector=selector,
                result=result,
            )
        except (OSError, ValueError, KeyError) as error:
            self.log("decision_error", error=str(error))

    def observe(self):
        attempts = Attempts()
        sensor_path = RUN / "sensor" / "eve.json"
        with sensor_path.open("rb") as stream:
            while True:
                line = stream.readline()
                if not line:
                    time.sleep(0.10)
                    continue
                if not line.endswith(b"\n"):
                    stream.seek(-len(line), 1)
                    time.sleep(0.10)
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(row, dict):
                    continue
                evidence = attempts.add(row, time.time())
                if evidence is None:
                    continue
                self.log(
                    "port80_observed",
                    evidence_id=evidence[-1],
                    window_attempts=len(evidence),
                )
                if len(evidence) >= THRESHOLD:
                    attempts.attempts.clear()
                    self.apply_policy(evidence)

    def run(self):
        self.publish()
        if self.args.drone == "drone-1":
            threading.Thread(
                target=self.observe, name="external-policy", daemon=True
            ).start()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            while True:
                start = time.monotonic()
                checks = {
                    name: pool.submit(self.poll, name, "/status") for name in self.peers
                }
                local = pool.submit(self.poll, self.args.drone, "/healthz")
                self.update_health(local.result())
                for name, future in checks.items():
                    peer = self.peers[name]
                    if peer.update(future.result()):
                        self.log(
                            "peer_stale" if peer.stale else "peer_fresh", peer=name
                        )
                self.log(
                    "health_tick",
                    local_ok=local.result() is not None,
                    cpu_usec=cgroup_cpu_usec(),
                    peers_ok={
                        name: future.result() is not None
                        for name, future in checks.items()
                    },
                )
                self.publish()
                time.sleep(max(0, 1 - (time.monotonic() - start)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--drone", required=True, choices=DRONES)
    parser.add_argument("--decoy", action="store_true")
    parser.add_argument("--model", action="store_true")
    Doctor(parser.parse_args()).run()


if __name__ == "__main__":
    main()
