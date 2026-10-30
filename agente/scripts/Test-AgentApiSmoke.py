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
    parser.add_argument("--executable", type=Path, help="Executável publicado; dispensa runtime/SDK no ensaio.")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    assembly = root / "SafeUpload.Agent.ApiSmoke/bin/Release/net10.0/SafeUpload.Agent.ApiSmoke.dll"
    if args.executable is not None and not args.executable.is_file():
        parser.error("Executável publicado não encontrado.")
    if args.executable is None and not assembly.is_file():
        parser.error("Compile SafeUpload.Agent.ApiSmoke em Release antes de executar.")
    command = [str(args.executable.resolve())] if args.executable else [args.dotnet, str(assembly)]
    requests = []
    scenario = {"status": 200, "body": '{"status":"OK"}'}
    stopping = threading.Event()

    def require(condition, message):
        # Não usar assert: python -O também deve detectar regressões.
        if not condition:
            raise RuntimeError(message)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            current = scenario.copy()
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
            requests.append({"method": "POST", "path": self.path, "body": json.loads(body)})
            payload = current["body"].encode()
            self.send_response(current["status"])
            if current["status"] == 302:
                self.send_header("Location", "/forbidden-followup")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.flush()
            # Cabeçalhos chegam imediatamente; o atraso é somente no corpo.
            stopping.wait(current.get("body_delay", 0))
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass  # Esperado quando o cliente encerra por timeout/limite.

        def do_GET(self):
            # Um redirecionamento 302 seguido pelo cliente pode virar GET.
            requests.append({"method": "GET", "path": self.path})
            self.send_error(500)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{server.server_port}/agent/"
    results = []
    try:
        for name, status, body, expected_exit, category, prefix, delay in [
            ("heartbeat-confirmed", 200, '{"status":"OK"}', 0, None, "", 0),
            ("unauthorized", 401, "SYNTHETIC-SECRET", 1, "http_status", "", 0),
            ("invalid-receipt", 200, '{"status":"WRONG"}', 1, "invalid_receipt", "", 0),
            ("redirect-refused", 302, "", 1, "http_status", "", 0),
            ("ambiguous-receipt", 200, '{"status":"OK","sta\\u0074us":"OK"}',
             1, "invalid_receipt", "", 0),
            ("oversized-receipt", 200, '{"status":"OK","padding":"' + "x" * 16384 + '"}',
             1, "receipt_too_large", "", 0),
            ("context-path-preserved", 200, '{"status":"OK"}', 0, None, "/context", 0),
            ("future-field-accepted", 200, '{"status":"OK","future":true}', 0, None, "", 0),
            ("body-timeout-after-headers", 200, '{"status":"OK"}', 1, "timeout", "", 7),
        ]:
            scenario.update(status=status, body=body, body_delay=delay)
            before = len(requests)
            target = f"http://127.0.0.1:{server.server_port}{prefix}/agent/"
            result = subprocess.run(command + ["--base-url", target,
                                     "--registered-host-id", "23"], capture_output=True,
                                    text=True, timeout=15)
            require(result.returncode == expected_exit, f"{name}: código de saída inesperado")
            require(requests[before:] == [{"method": "POST", "path": prefix + "/agent/heartbeat",
                                          "body": {"id_host": 23}}],
                    f"{name}: tráfego inesperado, retentativa ou redirecionamento")
            require("SYNTHETIC-SECRET" not in result.stdout + result.stderr,
                    f"{name}: saída expôs conteúdo do servidor")
            if category:
                require(f"categoria={category};" in result.stderr, f"{name}: categoria incorreta")
            results.append({"case": name, "passed": True, "exit_code": result.returncode,
                            "requests": len(requests) - before})
        for name, target, user_id in [
            ("invalid-id-no-http", url, "0"),
            ("invalid-id-format-no-http", url, "SID-23"),
            ("secret-query-rejected-no-http", url + "?token=SYNTHETIC-SECRET", "23"),
        ]:
            before = len(requests)
            invalid = subprocess.run(command + ["--base-url", target,
                                      "--registered-host-id", user_id], capture_output=True,
                                     text=True, timeout=15)
            require(invalid.returncode == 2 and len(requests) == before,
                    f"{name}: configuração inválida gerou tráfego ou código incorreto")
            require("SYNTHETIC-SECRET" not in invalid.stdout + invalid.stderr,
                    f"{name}: saída expôs configuração")
            results.append({"case": name, "passed": True, "exit_code": invalid.returncode,
                            "requests": 0})
        before = len(requests)
        old = subprocess.run(command + ["--base-url", url, "--registered-user-id", "23"],
                             capture_output=True, text=True, timeout=15)
        require(old.returncode == 2 and len(requests) == before,
                "old-user-option-no-http: opção antiga gerou tráfego ou código incorreto")
        results.append({"case": "old-user-option-no-http", "passed": True,
                        "exit_code": old.returncode, "requests": 0})
        print(json.dumps({"mode": "synthetic-loopback-http", "java_tested": False,
                          "service_installed": False, "results": results}, indent=2))
    finally:
        stopping.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    main()
