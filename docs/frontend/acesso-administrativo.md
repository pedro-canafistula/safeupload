# Acesso administrativo na interface web

Esta entrega atende à parte de navegação da HU-06 e da RN-008: somente contas com `role` igual a `admin` entram nas telas administrativas. O usuário final utiliza o agente no endpoint, não o painel web.

## Comportamento

- Antes de abrir uma tela administrativa, inclusive na navegação entre telas, a interface consulta `/api/auth/me`.
- Contas comuns, perfis desconhecidos ou vazios recebem uma página de acesso restrito, sem carregar os dados administrativos.
- A página permite encerrar a sessão e usar outra conta. Falhas no logout são informadas sem afirmar que a sessão foi encerrada.
- Uma resposta 401 na verificação da sessão encaminha ao login com aviso de sessão inativa.
- Falhas de conexão ou serviço exibem uma mensagem distinta, sem afirmar que a senha está incorreta ou que a sessão expirou.
- A verificação ocorre na navegação; não existe monitoramento contínuo de expiração enquanto o usuário permanece na mesma tela.

## Limites e dependência externa

O guard do Angular é uma barreira de navegação, não uma autorização de segurança da API. O servidor ainda precisa validar o perfil administrativo em cada operação protegida. Essa pendência pertence à equipe de backend; este PR não altera Java, banco, agente ou driver e não declara a HU-06 integralmente concluída.

O fluxo de cadastro existente não foi modificado. A definição de provisionamento de administradores também depende da equipe responsável pelo servidor.

## Validação

`npm test -- acesso-administrativo.spec.ts` executa cenários de interface com respostas HTTP simuladas: diferentes perfis, acesso direto às quatro telas, login comum, logout, expiração, mudança de perfil e indisponibilidade. Não depende de dados pessoais nem de um backend ativo. Esses testes não comprovam autorização no servidor.

`npm run build` valida a compilação de produção. A suíte `migration.spec.ts` continua cobrindo a integração com backend isolado, conforme as instruções de migração.

## Próximas entregas web

1. Detalhes da auditoria usando somente metadados já disponíveis na API (HU-04).
2. Mensagens que distingam aprovação, bloqueio e liberação sem inspeção, sem prometer ausência de risco.
3. Navegação e filtros do inventário de endpoints (HU-10).
4. Acessibilidade, responsividade e estados de carregamento, erro e vazio.

Categorias configuráveis dependem de contrato de API. Exceções e relatórios permanecem evoluções planejadas, não parte desta entrega.
