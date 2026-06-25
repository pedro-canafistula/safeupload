"""
Pacote da camada de apresentação.

Concentra rotas HTTP, templates Jinja2 e arquivos estáticos. Este módulo
expõe a instância ``templates`` compartilhada por todos os roteadores, de
forma que cada rota possa renderizar páginas sem precisar reconfigurar o
diretório de templates.
"""

from pathlib import Path

from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
