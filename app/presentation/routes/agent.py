"""
Rotas da interface pública do agente DLP.

Esta interface permite que o usuário final submeta arquivos para inspeção
sem necessidade de autenticação, conforme decisão registrada em
``DOC_CHANGES.md``.

Atualmente vazia — as páginas serão adicionadas conforme o protótipo
avança.
"""

from fastapi import APIRouter

router = APIRouter(tags=["agent"])
