"""Mission HTTPS service and low-interaction lab decoy."""

import argparse
import json
import socketserver
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

from common import DRONES, IDENTITY, STATUS, WAN_ADDRESS, read_json


class MissionHandler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(0.7)
        super().setup()

    def do_GET(self):
        certificate = self.connection.getpeercert()
        names = [
            value
            for group in certificate["subject"]
            for key, value in group
            if key == "commonName"
        ]
        if len(names) != 1 or names[0] not in DRONES:
            self.send_error(403)
            return
        if self.path == "/healthz":
            data = {"ok": True, "drone_id": self.server.drone}
        elif self.path == "/status":
            try:
                data = read_json(STATUS)
            except (OSError, ValueError):
                self.send_error(503)
                return
        else:
            self.send_error(404)
            return
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class MissionServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def process_request_thread(self, request, address):
        request.settimeout(0.7)
        try:
            with self.tls.wrap_socket(request, server_side=True) as secure:
                super().process_request_thread(secure, address)
        except OSError:
            self.shutdown_request(request)


class Decoy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(0.5)
        try:
            self.request.recv(1024)
            self.request.sendall(
                b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: 10\r\nConnection: close\r\n\r\nLab decoy\n"
            )
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("service", choices=["mission", "decoy"])
    parser.add_argument("--drone", choices=DRONES)
    args = parser.parse_args()
    if args.service == "decoy":
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer((WAN_ADDRESS, 80), Decoy) as server:
            print("ready", flush=True)
            server.serve_forever()
        return
    if not args.drone:
        parser.error("--drone is required for the mission service")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.verify_mode = ssl.CERT_REQUIRED
    tls.load_verify_locations(IDENTITY / "ca.crt")
    tls.load_cert_chain(IDENTITY / "node.crt", IDENTITY / "node.key")
    with MissionServer((DRONES[args.drone], 443), MissionHandler) as server:
        server.tls = tls
        server.drone = args.drone
        server.serve_forever()


if __name__ == "__main__":
    main()
