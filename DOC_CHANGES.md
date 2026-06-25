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
- **Documento de Requisitos — HU-04 (Registrar eventos em log de auditoria):** o critério de aceite que exige campo "usuário" no log precisa ser revisto. Para inspeções via interface do agente, registrar identificador anônimo de sessão (ou IP) em vez de usuário nomeado. Manter campo "usuário" apenas para ações administrativas.
- **Documento de Arquitetura — Seção 3 (Visão de Casos de Uso), Figura 2:** remover o caso "Autenticar-se" do ator "Usuário final" no diagrama UML; manter apenas para o ator "Administrador".
- **Documento de Arquitetura — Seção 8 (Visão de Dados), tabela AUDIT_EVENTS:** o campo `user_id` deve ser opcional (nullable) para suportar eventos sem usuário autenticado.

**Status:** ✅ Aceita — pendente atualização nos documentos.

---

## Concluídas

_(nenhuma ainda)_
