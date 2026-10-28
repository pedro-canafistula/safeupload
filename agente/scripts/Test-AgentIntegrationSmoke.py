"""Tests the published meeting utility against synthetic loopback HTTP, never a real backend."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    args = parser.parse_args()
    executable = str(args.executable.resolve())
    if not args.executable.is_file():
        parser.error("Published executable not found")
    calls = []
    scenario = {"heartbeat": 200, "audit": "valid"}
    results = []

    def require(condition, name):
        if not condition:
            raise RuntimeError(name)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                parts = []
                while True:
                    size = int(self.rfile.readline().strip().split(b";", 1)[0], 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    parts.append(self.rfile.read(size))
                    self.rfile.read(2)
                payload = b"".join(parts)
            else:
                payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append({"path": self.path, "body": json.loads(payload)})
            heartbeat = self.path.endswith("/heartbeat")
            status = scenario["heartbeat"] if heartbeat else 200
            body = '{"status":"OK"}' if heartbeat else '{"acceptedEvents":1,"acceptedOverrides":0}'
            if not heartbeat:
                if scenario["audit"] == "ambiguous":
                    body = '{"acceptedEvents":0,"acceptedEvents":1,"acceptedOverrides":0}'
                elif scenario["audit"] == "missing":
                    body = '{"acceptedEvents":1}'
                elif scenario["audit"] == "redirect":
                    status, body = 302, "SYNTHETIC_SECRET"
                elif scenario["audit"] == "drop":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
            self.send_response(status)
            if status == 302:
                self.send_header("Location", "/forbidden")
            encoded = body.encode()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
            calls.append({"path": self.path, "method": "GET"})
            self.send_error(500)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{server.server_port}/context/agent/"

    def invoke(mode, folder, expected=0, target=url, host="7"):
        command = [executable, mode, str(folder)]
        if mode in ("send", "replay"):
            command += ["--base-url", target, "--registered-host-id", host]
        result = subprocess.run(command, capture_output=True, text=True, timeout=25)
        require(result.returncode == expected, f"{mode}: unexpected exit {result.returncode}")
        require("SYNTHETIC_SECRET" not in result.stdout + result.stderr, "sensitive output")
        return json.loads(result.stdout) if result.stdout.strip() else None

    def case(name):
        results.append({"case": name, "passed": True})

    try:
        with tempfile.TemporaryDirectory(prefix="safeupload-meeting-fixture-") as root:
            root = Path(root)
            folder = root / "primary"
            report = invoke("prepare", folder)
            identity = report["eventId"]
            before = (folder / "meeting-queue.jsonl").read_bytes()
            require(report["pendingAfter"] == 1 and not calls, "prepare must be offline")
            case("offline-prepare")
            invoke("prepare", folder, expected=2)
            require((folder / "meeting-queue.jsonl").read_bytes() == before, "second prepare changed queue")
            case("existing-folder-preserved")
            report = invoke("status", folder)
            require(report["eventId"] == identity and report["pendingAfter"] == 1 and not calls, "offline status")
            case("process-reopen-offline-status")
            invoke("send", folder, expected=2, host="0")
            invoke("send", folder, expected=2, target=url + "?token=SYNTHETIC_SECRET")
            require(not calls, "invalid configuration sent traffic")
            case("invalid-configuration-no-http")

            with socket.socket() as offline:
                offline.bind(("127.0.0.1", 0))  # Reserved, but not listening.
                target = f"http://127.0.0.1:{offline.getsockname()[1]}/agent/"
                report = invoke("send", folder, expected=1, target=target)
            require(report["pendingAfter"] == 1 and not calls and
                    (folder / "meeting-queue.jsonl").read_bytes() == before, "offline attempt lost pending")
            case("offline-network-preserves-pending")

            scenario["audit"] = "ambiguous"
            report = invoke("send", folder, expected=1)
            first_payload = calls[-1]["body"]
            require(calls[-2]["path"] == "/context/agent/heartbeat" and calls[-2]["body"] == {"id_host": 7}, "heartbeat contract")
            require(calls[-1]["path"] == "/context/agent/events", "audit route")
            require(report["pendingAfter"] == 1 and (folder / "meeting-queue.jsonl").read_bytes() == before, "ambiguous receipt lost pending")
            case("ambiguous-receipt-preserves-bytes")
            scenario["audit"] = "valid"
            report = invoke("send", folder)
            require(report["pendingAfter"] == 0 and calls[-1]["body"] == first_payload, "retry changed original event")
            require(not report["centralPersistenceVerified"] and not report["installedServiceTested"], "false qualification")
            case("retry-same-payload-after-process-reopen")
            count = len(calls)
            report = invoke("send", folder)
            require(len(calls) == count + 1 and report["result"] == "already_confirmed", "empty queue invented event")
            case("confirmed-queue-does-not-resend")
            report = invoke("replay", folder)
            require(calls[-1]["body"] == first_payload and report["pendingAfter"] == 0, "explicit replay changed identity")
            require((folder / "meeting-queue.jsonl").read_bytes() != before, "original queue never confirmed")
            case("explicit-duplicate-uses-original-event")

            for name, audit_mode in [("missing-count-preserves-pending", "missing"), ("redirect-refused", "redirect"),
                                     ("lost-response-retry-same-event", "drop")]:
                test_folder = root / name
                invoke("prepare", test_folder)
                queue_before = (test_folder / "meeting-queue.jsonl").read_bytes()
                scenario["audit"] = audit_mode
                report = invoke("send", test_folder, expected=1)
                sent = calls[-1]["body"]
                require(report["pendingAfter"] == 1 and (test_folder / "meeting-queue.jsonl").read_bytes() == queue_before, name)
                require(not any(call.get("method") == "GET" for call in calls), "followed redirect")
                scenario["audit"] = "valid"
                report = invoke("send", test_folder)
                require(report["pendingAfter"] == 0 and calls[-1]["body"] == sent, name + " retry")
                case(name)

            failed_host = root / "failed-heartbeat"
            invoke("prepare", failed_host)
            scenario["heartbeat"] = 503
            report = invoke("send", failed_host, expected=1)
            require(report["pendingAfter"] == 0, "heartbeat blocked audit")
            states = {item["operation"]: item for item in report["communication"]["operations"]}
            require(states["Heartbeat"]["state"] == "Failure" and states["Audit"]["state"] == "Success", "operation independence")
            case("failed-heartbeat-does-not-block-audit")

            unrelated = root / "unrelated"
            unrelated.mkdir()
            (unrelated / "keep.txt").write_text("preserve")
            invoke("prepare", unrelated, expected=2)
            require((unrelated / "keep.txt").read_text() == "preserve", "modified unrelated folder")
            case("unrelated-folder-refused")
        print(json.dumps({"mode": "published-process-loopback", "javaTested": False, "serviceInstalled": False,
                          "results": results}, indent=2))
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    main()
