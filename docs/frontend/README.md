# Guia do frontend web SafeUpload

Este guia documenta o painel web existente e sua refatoração estrutural. A maior parte da interface ainda é demonstrativa. Auditoria e Endpoints já exibem somente dados recebidos pela API do agente, mantidos em memória; Endpoints também aplica filtros reais e liga cada máquina ao seu histórico de auditoria. Autenticação e persistência em banco não estão implementadas no servidor web. A inspeção pertence ao [agente desktop](../../agente/README.md).

## Conteúdo

- [Estrutura e layouts](estrutura.md)
- [Inventário das oito telas, comportamento e dependências](telas-e-dados.md)
- [Componentes e estilos](componentes-e-estilos.md)
- [Verificação e limitações](verificacao-e-limitacoes.md)

## Executar o painel

Na raiz do projeto, usando Python 3.11 ou superior:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Acesse `http://127.0.0.1:8000`. A raiz redireciona para o login. O formulário de login é demonstrativo e seu envio redireciona para o painel, sem validar as credenciais. Não use credenciais reais na demonstração.

As dependências usam versões mínimas, sem lockfile. As versões utilizadas na verificação desta entrega constam no registro de validação. Os testes desta etapa executaram a aplicação por TestClient; o comando de servidor acima é a forma de execução prevista pelo ponto de entrada, não uma etapa de instalação validada em uma segunda máquina.

## Estado desta entrega

A refatoração de templates está concluída: os layouts HTML usam uma base comum, a sidebar está em um include, SVGs reutilizados estão centralizados em `templates/components/icons.html` e a moldura dos avisos está em `templates/components/notice.html`. Os ícones das categorias são selecionados por uma chave conhecida no contexto, sem transportar SVG/HTML pelas rotas.

A organização do CSS também está concluída. `/static/css/styles.css` continua sendo o único stylesheet referenciado pelo HTML, mas agora importa `tokens.css`, `base.css`, `auth.css`, `controls.css`, `layout.css`, `components.css` e `pages.css` em ordem fixa. As regras originais foram apenas separadas; não houve renomeação de classes, mudança de valores nem reordenação da cascata.

Os seis contextos demonstrativos permanecem em `presentation/demo/admin_data.py`; Endpoints também lê heartbeats em memória. A Auditoria usa `presentation/audit.py`: a rota consulta `application/agent_service.py` e entrega os eventos ao builder de apresentação. Lista e totais usam os mesmos registros; ausência de eventos é exibida explicitamente. Filtros, detalhes, exportação e paginação não estão disponíveis nesse recorte.

O registro `validacao-final.json` documenta a conclusão de F06/F07 da refatoração em 16/09/2026. O inventário atualizado em 01/10/2026 descreve as oito telas e suas dependências, incluindo Auditoria somente para leitura. Os registros visuais históricos não certificam essa evolução.

O escopo de melhoria é o frontend web. O código do agente desktop é preservado sem alteração.
