"""Deterministic policy and bounded offline model selection."""

import http.client
import json
import time
from datetime import datetime

from common import OBSERVE_SID, TEST_CLIENT, WAN_ADDRESS, WAN_IFACE

WINDOW = 10
THRESHOLD = 3
BLOCK = "block_80"
DECOY = "start_decoy"


class Attempts:
    def __init__(self):
        self.seen = {}
        self.attempts = {}

    def add(self, row, now):
        self.attempts = {
            port: item for port, item in self.attempts.items() if item[0] > now - WINDOW
        }
        if (
            row.get("event_type"),
            row.get("in_iface"),
            row.get("src_ip"),
            row.get("dest_ip"),
            row.get("dest_port"),
            row.get("proto"),
        ) != ("alert", WAN_IFACE, TEST_CLIENT, WAN_ADDRESS, 80, "TCP"):
            return None
        try:
            if row["alert"]["signature_id"] != OBSERVE_SID:
                return None
            port = row["src_port"]
            observed = datetime.fromisoformat(row["timestamp"]).timestamp()
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
            return None
        if (
            type(port) is not int
            or not 0 < port < 65536
            or not now - WINDOW < observed <= now + 1
        ):
            return None
        if self.seen.get(port, 0) > now - WINDOW:
            return None
        self.seen[port] = observed
        flow_id = row.get("flow_id")
        evidence_id = f"syn:{port}:{flow_id if type(flow_id) is int else '-'}"
        self.attempts[port] = (observed, evidence_id)
        return [evidence for _, evidence in self.attempts.values()]


def choices(decoy_enabled, service_healthy, resources_ok):
    if decoy_enabled and service_healthy and resources_ok:
        return [DECOY, BLOCK]
    return [BLOCK]


def choose_model(actions, evidence, mission_phase, service_healthy, resources_ok):
    """The first action is the rules baseline. Model output has no execution parameters."""
    facts = {
        "allowed_actions": actions,
        "evidence_ids": evidence,
        "mission_phase": mission_phase,
        "https_healthy": service_healthy,
        "resources_ok": resources_ok,
    }
    instruction = (
        "Select a defensive action for repeated external port 80 attempts in an isolated lab. "
        "Prefer start_decoy when allowed and healthy with adequate resources, otherwise block_80. "
        "Reply with one JSON object with action_id and evidence_ids. Cite observed evidence IDs."
    )
    request = {
        "model": "local",
        "messages": [
            {"role": "system", "content": instruction},
            {"role": "user", "content": json.dumps(facts)},
        ],
        "temperature": 0,
        "max_tokens": 100,
        "response_format": {"type": "json_object"},
    }
    deadline = time.monotonic() + 2
    connection = http.client.HTTPConnection("127.0.0.1", 8088, timeout=2)
    try:
        connection.request(
            "POST",
            "/v1/chat/completions",
            json.dumps(request),
            {"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"HTTP {response.status}")
        payload = json.loads(response.read(16385))
        answer = json.loads(payload["choices"][0]["message"]["content"])
        action, ids = answer["action_id"], answer["evidence_ids"]
        if (
            set(answer) != {"action_id", "evidence_ids"}
            or action not in actions
            or not isinstance(ids, list)
            or not ids
            or not all(isinstance(item, str) and item in evidence for item in ids)
            or time.monotonic() > deadline
        ):
            raise ValueError("invalid or late decision")
        return action, ids, "model"
    except (
        OSError,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        http.client.HTTPException,
    ) as error:
        return actions[0], evidence, f"rules_fallback:{type(error).__name__}"
    finally:
        connection.close()
