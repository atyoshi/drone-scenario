"""Focused checks that run without Docker, CORE, or live network access."""

import json
import shutil
import ssl
import struct
import subprocess
import tempfile
import time
import unittest
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from common import (
    DRONES,
    IPS_SID,
    MARKER_PATH,
    OBSERVE_SID,
    TEST_CLIENT,
    WAN_ADDRESS,
    WAN_IFACE,
    client_tls,
)
from doctor import Doctor, Peer
from guard import firewall
from policy import BLOCK, DECOY, Attempts, choices, choose_model
from scenario import Lab, make_credentials

APP = Path(__file__).resolve().parents[1]


class CollectionTests(unittest.TestCase):
    def test_collect_creates_missing_case_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab = Lab.__new__(Lab)
            lab.directory = Path(tmp) / "run" / "rules-firewall"
            lab.timeline = []
            lab.events = Mock(return_value=[])
            lab.node = Mock(return_value="")
            lab.collect()
            self.assertTrue((lab.directory / "drone-1-guard.log").is_file())
            self.assertTrue((lab.directory / "timeline.jsonl").is_file())

    def test_recovery_wait_allows_polling_delay_but_checks_event_time(self):
        lab = Lab.__new__(Lab)
        lab.crash_window = [100.0, None]
        lab.seek_event = Mock(return_value={"ts": 109.9})
        lab.check = Mock()
        lab.crash_finish()
        self.assertGreater(lab.seek_event.call_args.kwargs["timeout"], 10)
        self.assertTrue(lab.check.call_args.args[1])


def eve(port, now, **changes):
    return {
        "event_type": "alert",
        "in_iface": WAN_IFACE,
        "src_ip": TEST_CLIENT,
        "dest_ip": WAN_ADDRESS,
        "dest_port": 80,
        "proto": "TCP",
        "src_port": port,
        "flow_id": 100 + port,
        "timestamp": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "alert": {"signature_id": OBSERVE_SID},
        **changes,
    }


class PolicyTests(unittest.TestCase):
    def test_distinct_fresh_attempts_and_retransmits(self):
        start = time.time()
        attempts = Attempts()
        self.assertIsNone(attempts.add(eve(40000, start - 11), start))
        self.assertIsNone(attempts.add(eve(40001, start, in_iface="mission0"), start))
        self.assertEqual(len(attempts.add(eve(40002, start), start)), 1)
        self.assertIsNone(attempts.add(eve(40002, start, flow_id=777), start))
        self.assertEqual(len(attempts.add(eve(40003, start), start)), 2)
        self.assertEqual(len(attempts.add(eve(40004, start), start)), 3)
        attempts.attempts.clear()
        self.assertIsNone(attempts.add(eve(40004, start + 1), start + 1))
        self.assertEqual(len(attempts.add(eve(40004, start + 11), start + 11)), 1)

    def test_policy_demands_healthy_mission_and_resources_for_decoy(self):
        self.assertEqual(choices(True, True, True), [DECOY, BLOCK])
        self.assertEqual(choices(False, True, True), [BLOCK])
        self.assertEqual(choices(True, False, True), [BLOCK])
        self.assertEqual(choices(True, True, False), [BLOCK])

    @patch("policy.http.client.HTTPConnection")
    def test_model_selection_is_bounded_by_actions_and_evidence(self, factory):
        response = Mock(status=200)
        factory.return_value.getresponse.return_value = response
        cases = [
            ({"action_id": BLOCK, "evidence_ids": ["ev1"]}, BLOCK, "model"),
            (
                {"action_id": "arbitrary", "evidence_ids": ["ev1"]},
                DECOY,
                "rules_fallback:ValueError",
            ),
            (
                {"action_id": BLOCK, "evidence_ids": ["forged"]},
                DECOY,
                "rules_fallback:ValueError",
            ),
            (
                {"action_id": BLOCK, "evidence_ids": ["ev1"], "port": 443},
                DECOY,
                "rules_fallback:ValueError",
            ),
        ]
        for answer, expected, selector in cases:
            response.read.return_value = json.dumps(
                {"choices": [{"message": {"content": json.dumps(answer)}}]}
            ).encode()
            with self.subTest(answer=answer):
                action, _, method = choose_model(
                    [DECOY, BLOCK], ["ev1"], "survey", True, True
                )
                self.assertEqual((action, method), (expected, selector))
        factory.return_value.request.side_effect = TimeoutError
        self.assertEqual(
            choose_model([BLOCK], ["ev1"], "survey", True, False),
            (BLOCK, ["ev1"], "rules_fallback:TimeoutError"),
        )

    def test_peer_hysteresis_preserves_last_report(self):
        peer = Peer()
        report = {"position": {"x": 25, "y": 40}, "incident": "none"}
        self.assertFalse(peer.update(report))
        self.assertTrue(peer.update(report))
        self.assertFalse(peer.stale)
        for _ in range(2):
            self.assertFalse(peer.update(None))
        self.assertTrue(peer.update(None))
        self.assertTrue(peer.stale)
        self.assertEqual(peer.position, report["position"])
        self.assertFalse(peer.update(report))
        self.assertTrue(peer.update(report))
        self.assertFalse(peer.stale)

    @patch("doctor.local_request", return_value={"ok": True})
    def test_recovery_requires_two_checks_and_bounds_restarts(self, request):
        doctor = Doctor.__new__(Doctor)
        doctor.bad_health = doctor.good_health = 0
        doctor.health = "healthy"
        doctor.recovering = False
        doctor.restart_times = deque()
        doctor.log = Mock()
        doctor.update_health(None)
        request.assert_not_called()
        doctor.update_health(None)
        request.assert_called_once_with("restart_https")
        doctor.update_health({"ok": True})
        self.assertEqual(doctor.health, "degraded")
        doctor.update_health({"ok": True})
        self.assertEqual(doctor.health, "healthy")
        doctor.log.assert_called_with("https_recovered", verified=True)
        for _ in range(4):
            doctor.update_health(None)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(doctor.health, "degraded")

    def test_firewall_is_scoped_and_queue_has_no_bypass(self):
        rules = firewall()
        self.assertIn(
            f'iifname "{WAN_IFACE}" ip saddr {TEST_CLIENT} ip daddr {WAN_ADDRESS} tcp dport 80',
            rules,
        )
        self.assertIn("counter name blocked_hits drop", rules)
        self.assertIn("meta skuid 18083 drop", rules)
        self.assertNotIn("bypass", rules)
        self.assertNotIn("443", rules)


def handshake(client_context, server_context, address):
    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_in, client_out, server_hostname=address)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    finished = [False, False]
    for _ in range(20):
        for index, connection, output, other_input in [
            (0, client, client_out, server_in),
            (1, server, server_out, client_in),
        ]:
            if not finished[index]:
                try:
                    connection.do_handshake()
                    finished[index] = True
                except ssl.SSLWantReadError:
                    pass
            data = output.read()
            if data:
                other_input.write(data)
        if all(finished):
            return server.getpeercert()
    raise RuntimeError("TLS handshake did not complete")


@unittest.skipUnless(
    shutil.which("openssl"), "OpenSSL CLI needed to generate lab identities"
)
class MutualTLSTests(unittest.TestCase):
    def test_trusted_peer_and_reject_untrusted_peer_or_wrong_server_ip(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            make_credentials(directory)
            target = directory / "drone-1"
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.verify_mode = ssl.CERT_REQUIRED
            server.load_verify_locations(target / "ca.crt")
            server.load_cert_chain(target / "node.crt", target / "node.key")
            peer = client_tls(directory / "drone-2")
            self.assertEqual(
                handshake(peer, server, DRONES["drone-1"])["subject"],
                ((("commonName", "drone-2"),),),
            )
            invalid = client_tls(directory / "drone-2", authenticated=False)
            invalid.load_cert_chain(
                directory / "bad-client" / "node.crt",
                directory / "bad-client" / "node.key",
            )
            with self.assertRaises(ssl.SSLError):
                handshake(invalid, server, DRONES["drone-1"])
            with self.assertRaises(ssl.SSLError):
                handshake(peer, server, DRONES["drone-2"])


def packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    import ipaddress

    ethernet = bytes.fromhex("0011223344556655443322110800")
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40 + len(payload),
        1,
        0,
        64,
        6,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 8192, 0, 0)
    return ethernet + ipv4 + tcp + payload


def pcap(destination, packets):
    with destination.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        seconds = int(time.time())
        for index, data in enumerate(packets):
            stream.write(
                struct.pack("<IIII", seconds, index * 1000, len(data), len(data))
            )
            stream.write(data)


def http_exchange(port, path):
    return [
        packet(TEST_CLIENT, WAN_ADDRESS, port, 80, 100, 0, 2),
        packet(WAN_ADDRESS, TEST_CLIENT, 80, port, 500, 101, 18),
        packet(TEST_CLIENT, WAN_ADDRESS, port, 80, 101, 501, 16),
        packet(
            TEST_CLIENT,
            WAN_ADDRESS,
            port,
            80,
            101,
            501,
            24,
            f"GET {path} HTTP/1.1\r\nHost: drone-lab\r\n\r\n".encode(),
        ),
    ]


@unittest.skipUnless(shutil.which("suricata"), "Suricata needed for packet replay")
class SuricataReplayTests(unittest.TestCase):
    def replay(self, packets, rules, inline=False):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            capture = directory / "fixture.pcap"
            pcap(capture, packets)
            result = subprocess.run(
                [
                    "suricata",
                    "-c",
                    str(APP / "suricata.yaml"),
                    "-S",
                    str(APP / rules),
                    "-l",
                    root,
                    "-k",
                    "none",
                    "-r",
                    str(capture),
                    *(["--simulate-ips"] if inline else []),
                ],
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return [
                json.loads(line)
                for line in (directory / "eve.json").read_text().splitlines()
            ]

    def test_passive_replay_produces_threshold_with_duplicate_packet(self):
        syn = packet(TEST_CLIENT, WAN_ADDRESS, 44000, 80, 100, 0, 2)
        rows = self.replay(
            [
                syn,
                syn,
                packet(TEST_CLIENT, WAN_ADDRESS, 44001, 80, 100, 0, 2),
                packet(TEST_CLIENT, WAN_ADDRESS, 44002, 80, 100, 0, 2),
            ],
            "observe.rules",
        )
        evidence = Attempts()
        counts = []
        for row in rows:
            self.assertEqual(row["alert"]["signature_id"], OBSERVE_SID)
            # PCAP has no live interface label. Supply the configured capture interface here.
            accepted = evidence.add({**row, "in_iface": WAN_IFACE}, time.time())
            if accepted:
                counts.append(len(accepted))
        self.assertEqual(counts, [1, 2, 3])

    def test_simulated_inline_reports_marker_drop_only(self):
        rows = self.replay(
            [*http_exchange(44100, "/"), *http_exchange(44101, MARKER_PATH)],
            "inline.rules",
            inline=True,
        )
        self.assertEqual(
            [
                (row["src_port"], row["alert"]["signature_id"], row["alert"]["action"])
                for row in rows
            ],
            [(44101, IPS_SID, "blocked")],
        )


if __name__ == "__main__":
    unittest.main()
