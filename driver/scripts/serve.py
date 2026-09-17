"""Serve o pacote para a VM alvo e recebe os resultados de volta.

GET  -> serve os arquivos do pacote, como o http.server padrao.
POST /resultados -> grava o corpo num arquivo, um por execucao.

Existe porque o http.server so faz GET, e sem o caminho de volta os
resultados da VM alvo voltavam por captura de tela: ilegivel, incompleto e
impossivel de comparar entre execucoes.

Os resultados sao gravados FORA do diretorio servido, de proposito. Um
diretorio que e servido por HTTP e legivel por qualquer coisa na rede local,
e resultado de execucao carrega caminho de arquivo, nome de maquina e o que
foi bloqueado.
"""

import datetime
import http.server
import pathlib
import re
import sys

PACKAGE = pathlib.Path(sys.argv[1]).resolve()
RESULTS = pathlib.Path(sys.argv[2]).resolve()
PORT = int(sys.argv[3])

# Um corpo grande demais nao e resultado de teste, e ou defeito ou abuso. O
# relatorio tipico tem alguns milhares de bytes.
MAX_BODY = 4 * 1024 * 1024

RESULTS.mkdir(parents=True, exist_ok=True)


class Handler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PACKAGE), **kwargs)

    def do_POST(self):
        if self.path.rstrip("/") != "/resultados":
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Content-Length invalido")
            return

        if length <= 0 or length > MAX_BODY:
            self.send_error(413, "corpo ausente ou grande demais")
            return

        body = self.rfile.read(length)

        # O nome vem do cliente, entao nao pode virar caminho: so letras,
        # digitos, ponto, hifen e sublinhado sobrevivem. Sem isto um
        # cabecalho com ".." escreveria fora do diretorio de resultados.
        raw = self.headers.get("X-SafeUpload-Run", "execucao")
        safe = re.sub(r"[^A-Za-z0-9._-]", "-", raw)[:80] or "execucao"

        stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        target = RESULTS / f"{stamp}_{safe}.txt"
        target.write_bytes(body)

        print(f"\n>>> resultados recebidos: {target}  ({len(body):,} bytes)\n", flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(f"gravado em {target.name}\n".encode("utf-8"))

    def log_message(self, fmt, *args):
        # O log padrao imprime uma linha por arquivo baixado, o que soterra
        # o aviso de resultado recebido. Downloads nao interessam; erros sim.
        if not str(args[1] if len(args) > 1 else "").startswith("2"):
            super().log_message(fmt, *args)


if __name__ == "__main__":
    print(f"Servindo {PACKAGE} na porta {PORT}.")
    print(f"Resultados chegam em {RESULTS}.")
    print("Ctrl+C para parar.\n", flush=True)

    with http.server.ThreadingHTTPServer(("", PORT), Handler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nServidor encerrado.")
