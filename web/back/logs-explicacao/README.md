# Logs do backend SafeUpload

Os logs são voltados a diagnóstico operacional e investigação básica de segurança. Eles são enviados ao console e gravados em `logs/safeupload.log` na raiz do repositório quando iniciados pelo comando documentado em [`grafana-lab/README.md`](../../../grafana-lab/README.md), para coleta pelo Alloy.

## Onde cada log é produzido

- `src/main/java/com/safeupload/presentation/filter/RequestLogFilter.java`: uma linha por requisição HTTP com ID de correlação, método, rota mapeada, status e duração. Respostas `4xx` usam `WARN` e o evento `http.request.rejected`; as demais usam `INFO`. O request ID gerado pelo servidor também é devolvido no cabeçalho `X-Request-ID`.
- `src/main/java/com/safeupload/application/AuthService.java`: login com sucesso/falha, bloqueio de conta e cadastro inicial/normalizado. Para login inválido, os motivos permanecem genéricos e não identificam o usuário informado.
- `src/main/java/com/safeupload/agent/AgentAuthFilter.java`: recusas de autenticação do agente por assinatura ausente/inválida, horário fora da janela, repetição, host revogado ou corpo excessivo. Cabeçalhos criptográficos e identificadores não validados não são incluídos.
- `src/main/java/com/safeupload/audit/AgentAdminController.java`: atribuição de grupo/revogação de host e emissão/exclusão de tokens de cadastro. O valor do token nunca é registrado.
- `src/main/java/com/safeupload/policy/PolicyAdminController.java`: criação/alteração/exclusão de políticas e grupos, usando IDs internos e sem copiar nomes ou configurações completas.
- `src/main/java/com/safeupload/presentation/exception/ApiExceptionHandler.java`: recusas `4xx` são registradas como `api.request.rejected`, com status e categoria fixa. Falhas do banco e erros inesperados são resumidos por tipo de exceção, sem despejar mensagem SQL, valores do corpo ou stack trace nos logs da aplicação.
- `src/main/resources/logback-spring.xml`: grava no console e em arquivo, inclui o request ID do MDC, rotaciona por tamanho/data e limita armazenamento/retencão.

## Campos e dados proibidos

Os eventos usam nomes fixos, IDs numéricos internos, categorias e métricas. Não registrar senhas, tokens, cookies, IDs de sessão, chaves, assinaturas, nonces, cabeçalhos de autenticação, corpos HTTP, conteúdo de arquivos, CPF/CNPJ, e-mail ou valores de regras. Não habilitar logs de valores SQL. O request ID não é uma credencial: ele é aleatório, gerado pelo backend e útil apenas para correlação.

As linhas de requisição usam padrões de rota do Spring, não query strings. Requisições sem rota mapeada aparecem como `unmatched` para não guardar segmentos controlados pelo solicitante.

## Consultar e executar

Para executar o Grafana/Loki/Alloy e pesquisar os logs, siga [`grafana-lab/README.md`](../../../grafana-lab/README.md). O diretório de saída `logs/` é ignorado pelo git. O Logback mantém no máximo sete dias e 200 MB de arquivos locais; Loki mantém sete dias. A trilha de auditoria funcional continua separada e não deve ser substituída por estes logs técnicos.

Níveis padrão: `INFO` para a aplicação, `WARN` para Spring Security e `WARN` para SQL do Hibernate. Não habilite `DEBUG`/`TRACE` indiscriminadamente em ambientes com dados reais.
