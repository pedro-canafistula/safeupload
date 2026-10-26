#!/usr/bin/env python3
"""Exercita o ApiSmoke por HTTP local sintético. NÃO inicia nem simula aceite do Java real.

Depois do build Release: python agente/scripts/Test-AgentApiSmoke.py
Requer Python 3 e dotnet no PATH (ou --dotnet /caminho/dotnet).
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", default="dotnet")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    assembly = root / "SafeUpload.Agent.ApiSmoke/bin/Release/net10.0/SafeUpload.Agent.ApiSmoke.dll"
    if not assembly.is_file():
        parser.error("Compile SafeUpload.Agent.ApiSmoke em Release antes de executar.")
    requests = []
    scenario = {"status": 200, "body": '{"status":"OK"}'}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            # JsonContent pode usar Transfer-Encoding chunked.
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                chunks = []
                while True:
                    length = int(self.rfile.readline().strip().split(b";", 1)[0], 16)
                    if length == 0:
                        self.rfile.readline()
                        break
                    chunks.append(self.rfile.read(length))
                    self.rfile.read(2)
                body = b"".join(chunks)
            requests.append({"path": self.path, "body": json.loads(body)})
            payload = scenario["body"].encode()
            self.send_response(scenario["status"])
            if scenario["status"] == 302:
                self.send_header("Location", "/forbidden-followup")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{server.server_port}/agent/"
    results = []
    try:
        for name, status, body, expected_exit in [
            ("heartbeat-confirmed", 200, '{"status":"OK"}', 0),
            ("unauthorized", 401, "SYNTHETIC-SECRET", 1),
            ("invalid-receipt", 200, '{"status":"WRONG"}', 1),
            ("redirect-refused", 302, "", 1),
        ]:
            scenario.update(status=status, body=body)
            before = len(requests)
            result = subprocess.run([args.dotnet, str(assembly), "--base-url", url,
                                     "--registered-user-id", "23"], capture_output=True,
                                    text=True, timeout=15)
            assert result.returncode == expected_exit, (name, result.stdout, result.stderr)
            assert requests[before:] == [{"path": "/agent/api/heartbeat", "body": {"id_usuario_so": 23}}], name
            assert "SYNTHETIC-SECRET" not in result.stderr, name
            results.append({"case": name, "passed": True, "exit_code": result.returncode,
                            "requests": len(requests) - before})
        before = len(requests)
        invalid = subprocess.run([args.dotnet, str(assembly), "--base-url", url,
                                  "--registered-user-id", "0"], capture_output=True, text=True, timeout=15)
        assert invalid.returncode == 2 and len(requests) == before
        results.append({"case": "invalid-id-no-http", "passed": True, "requests": 0})
        print(json.dumps({"mode": "synthetic-loopback-http", "java_tested": False,
                          "service_installed": False, "results": results}, indent=2))
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    main()
