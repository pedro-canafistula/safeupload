"""
Ponto de entrada da aplicação SafeUpload.

Inicializa a aplicação FastAPI, monta o diretório de arquivos estáticos em
``/static`` e registra os roteadores das duas áreas do produto:

- :mod:`app.presentation.routes.admin`: Centro de Administração (rotas em ``/admin``).
- :mod:`app.presentation.routes.agent`:  Interface pública do agente DLP
  (rotas para envio de arquivos pelo usuário final).

Para executar localmente::

    uvicorn app.main:app --reload
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.presentation.routes import admin, agent

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "presentation" / "static"

app = FastAPI(title="SafeUpload", version="0.1.0")

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(admin.router)
app.include_router(agent.router)


@app.get("/", include_in_schema=False)
async def root():
    """Redireciona a raiz para a tela de login do Centro de Administração.

    Temporário enquanto a interface do agente ainda não está implementada.
    """
    return RedirectResponse(url="/admin/login")
