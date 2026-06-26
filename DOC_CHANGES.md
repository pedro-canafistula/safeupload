# Mudanças Pendentes na Documentação

Este arquivo rastreia decisões de design tomadas durante o desenvolvimento do protótipo que **precisam ser refletidas nos documentos oficiais** (Visão, Requisitos, Arquitetura). Cada item descreve a decisão, o motivo e quais trechos dos documentos devem ser atualizados.

---

## Pendentes

### 1. Remoção do login na interface do agente (DLP)

**Data da decisão:** 2026-06-23

**Decisão:** O usuário final **não precisa autenticar-se** para submeter arquivos à inspeção. A interface de upload é de acesso aberto. Apenas o Centro de Administração exige login.

**Motivo:** Alinhamento com o comportamento de soluções DLP comerciais (ex.: Forcepoint, Symantec DLP). Nessas ferramentas, o componente que inspeciona arquivos opera inline, sem exigir autenticação do usuário final.

**Trechos a alterar:**

- **Documento de Requisitos — HU-06 (Autenticar usuário e controlar acesso):** restringir o escopo da história ao perfil administrador. O texto atual "Como usuário cadastrado, quero autenticar-me antes de utilizar a aplicação" precisa ser ajustado para refletir que apenas administradores fazem login.
- **Documento de Requisitos — HU-04 (Registrar eventos em log de auditoria):** o critério de aceite que exige campo "usuário" no log precisa ser revisto. Para inspeções via agente desktop, registrar identificador de sessão/hostname em vez de usuário nomeado. Manter campo "usuário" apenas para ações administrativas.
- **Documento de Arquitetura — Seção 3 (Visão de Casos de Uso), Figura 2:** remover o caso "Autenticar-se" do ator "Usuário final" no diagrama UML; manter apenas para o ator "Administrador".
- **Documento de Arquitetura — Seção 8 (Visão de Dados), tabela AUDIT_EVENTS:** o campo `user_id` deve ser opcional (nullable) para suportar eventos sem usuário autenticado.

**Status:** ✅ Aceita — pendente atualização nos documentos.

---

### 2. Mudança de modelo arquitetural — de upload web para agente desktop

**Data da decisão:** 2026-06-26

**Decisão:** O SafeUpload passa a ser um **sistema de dois componentes**, seguindo o modelo Forcepoint/Symantec DLP:

1. **Agente desktop** — aplicação Windows instalada nos endpoints dos usuários. Intercepta operações de arquivo (salvar, compartilhar, enviar) e submete o conteúdo ao servidor central para inspeção via API.
2. **Centro de Administração** — aplicação web (FastAPI + browser) usada pelos administradores para gestão de endpoints, auditoria, categorias e usuários. **Este componente continua sendo uma aplicação web** — o fato de o agente ser desktop não altera a natureza do painel de administração.

O modelo original descrito nos documentos — onde o próprio usuário vai a uma interface web e carrega o arquivo manualmente — **não será implementado**. A inspeção acontece de forma transparente via agente, sem intervenção do usuário.

**Motivo:** O modelo de "browser upload" é adequado para MVPs de demonstração, mas não reflete como soluções DLP reais operam. O objetivo do projeto é aproximar-se de uma implementação realista. A tela `/admin/endpoints` já implementada é a interface de gestão desses agentes.

**Trechos a alterar:**

- **Documento de Visão — Seção de Descrição do Produto (p.2/3):** substituir "aplicação web onde o usuário envia arquivos" por descrição do sistema de dois componentes: agente desktop + painel de administração web.
- **Documento de Requisitos — HU-01 (Inspecionar arquivo submetido):** reformular de "usuário acessa interface web e faz upload" para "agente desktop intercepta operação de arquivo e envia ao servidor para inspeção". A história de usuário muda de perspectiva: o ator é o sistema, não o usuário final.
- **Documento de Requisitos — HU-02 e HU-03 (Detectar e Bloquear):** manter a lógica de detecção e bloqueio, mas o contexto muda: a resposta vai para o agente desktop, que então bloqueia ou libera a operação de arquivo no endpoint.
- **Documento de Requisitos — HU-05 (Exibir motivo do bloqueio):** o motivo do bloqueio é exibido pelo agente desktop (notificação Windows/tray), não por uma página web.
- **Documento de Arquitetura — Seção 1 (Introdução / Escopo):** incluir o agente desktop como componente do sistema.
- **Documento de Arquitetura — Seção 4 (Visão Lógica):** incluir o pacote `agent/` (aplicação desktop) com sua comunicação com o servidor.
- **Documento de Arquitetura — Seção 5 (Visão de Processo), Figura 5 (diagrama de sequência):** o fluxo atual mostra `Browser → POST /api/inspect`. Deve mostrar `AgentDesktop → POST /api/inspect → Servidor → resposta → AgentDesktop → bloqueia/libera operação`.
- **Documento de Arquitetura — Seção 6 (Visão de Implantação):** adicionar diagrama com dois nós: Endpoint (agente desktop Windows) e Servidor Central (FastAPI + SQLite). O browser do admin acessa o servidor; o agente acessa a API de inspeção.
- **Documento de Arquitetura — Seção 7 (Visão de Implementação):** incluir estrutura do agente desktop (linguagem, empacotamento, comunicação com API). A rota `POST /api/inspect` documentada na Figura 5 permanece válida como interface entre agente e servidor, mas deixa de ser chamada por um browser.

**Status:** ✅ Aceita — pendente atualização abrangente nos três documentos.

---

### 3. Perfil "Auditor" não documentado nos requisitos

**Data da decisão:** 2026-06-26

**Decisão:** A tela `/admin/usuarios` implementa dois perfis distintos de acesso: **Administrador** e **Auditor**. O perfil Auditor tem acesso de leitura ao painel, auditoria e relatórios, mas não gerencia categorias, exceções nem usuários.

**Motivo:** Em soluções DLP reais (Forcepoint, Symantec), existe separação entre quem configura o sistema (administrador) e quem audita eventos (auditor de segurança ou compliance). A distinção é relevante para conformidade e segurança.

**Trechos a alterar:**

- **Documento de Requisitos — HU-06 (Autenticar usuário e controlar acesso):** incluir o perfil Auditor, definindo quais funcionalidades cada perfil acessa. Sugestão: Administrador acessa tudo; Auditor acessa somente Painel, Auditoria e Relatórios (leitura).
- **Documento de Arquitetura — Seção 3 (Visão de Casos de Uso), Figura 2:** adicionar o ator "Auditor" e seus casos de uso correspondentes.
- **Documento de Arquitetura — Seção 8 (Visão de Dados), tabela USERS:** confirmar que a coluna `perfil` aceita os valores `administrador` e `auditor` (enum).
- **Documento de Requisitos — RN-008 (Controle de acesso por perfil):** adicionar tabela explícita de permissões por perfil.

**Status:** ✅ Aceita — pendente atualização nos documentos.

---

### 4. Rota `/api/inspect` nomeada na Arquitetura não reflete a implementação real

**Data da decisão:** 2026-06-26

**Decisão:** O Documento de Arquitetura (Seção 5, Figura 5) nomeia a rota de inspeção como `POST /api/inspect`, chamada a partir de um browser. Com a mudança para agente desktop (item 2), essa rota continua válida como contrato de API entre agente e servidor, mas não será chamada por um browser — e seu path será definido durante a implementação do agente.

**Trechos a alterar:**

- **Documento de Arquitetura — Seção 5, Figura 5:** manter `POST /api/inspect` como rota da API de inspeção, mas ajustar o diagrama para mostrar que o chamador é o agente desktop, não um browser. A rota pertence ao router `agent.py` (atualmente vazio), que será implementado quando o agente desktop for desenvolvido.

**Status:** ✅ Aceita — pendente ajuste no diagrama de sequência.

---

## Concluídas

_(nenhuma ainda)_
