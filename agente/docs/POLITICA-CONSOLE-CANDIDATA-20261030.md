# Política da console — candidata local de 30/10/2026

Implementação C# sobre 03a64d07 do #64, para o contrato publicado na main 6e4ec708. A branch anunciada por Pedro ainda não estava disponível na consulta. Lucas informou que Pedro fez alterações para teste e pretende publicar amanhã. Comparar e reaproveitar sua entrega antes de decidir qualquer publicação desta candidata.

## Configuração explícita

O serviço pode consultar GET /agent/api/policy?ip=..., conferir destino.idHost contra a identidade provisionada e traduzir a resposta administrativa. A configuração existente continua usando o consumidor legado.

Exemplo somente para ambiente sintético, com host 23 previamente provisionado e IP de documentação cadastrado naquele host:

~~~json
{
  "CentroAdministracao": {
    "BaseUrl": "http://127.0.0.1:8080/agent/",
    "HeartbeatProtocol": "AgentApi",
    "RegisteredHostId": 23,
    "PolicyProtocol": "ConsoleByIp",
    "PolicyHostIp": "192.0.2.10"
  }
}
~~~

Após o provisionamento inicial, RegisteredHostId pode ser omitido se o vínculo protegido já existir para o mesmo servidor, conforme o #64. IP não é descoberto automaticamente e não substitui identidade. A resposta precisa corresponder tanto ao IP configurado quanto ao id_host. Não há cadastro automático, troca de identidade ou fallback entre protocolos.

A configuração operacional permanece no arquivo local protegido %ProgramData%\SafeUpload\policy.json: escopos, extensões, tamanho/prazo, processos excluídos e configuração de clipboard. Conferir esse arquivo antes de ativar o modo. Se estiver ausente, o mecanismo local existente cria seu padrão; esta candidata não define novos padrões de escopo.

## Tradução e revisões

| Console | Política efetiva |
|---|---|
| cpf | Cpf |
| cnpj | Cnpj |
| cartao_credito | PaymentCard |
| credenciais | Password e Secret |
| acao=bloquear | AuditOnly=false, OverrideAllowed=false |
| acao=alertar | AuditOnly=true, OverrideAllowed=false |
| idPolitica positivo | Policy.Version |

A console atual envia versao="1.0" em todas as publicações; isso não distingue atualizações. A compatibilidade inicial aceita esse valor textual e usa idPolitica como revisão da publicação. É um mapeamento desta candidata, a alinhar com os responsáveis.

Regras desconhecidas, inclusive uma combinação de regra suportada com RG/saúde/dados bancários, recusam a política inteira. Não se apresenta uma fração como aplicação completa. Comparar esse comportamento com o código do Pedro. Ações diferentes de bloquear/alertar são recusadas. Justificativa permanece desabilitada neste modo. O AuditOnly global conserva o comportamento existente dos canais, inclusive o modo efetivo do clipboard.

Respostas incompletas, IDs/destino divergentes, campos repetidos e revisões regressivas ou alteradas sem nova publicação preservam a última política válida. Leitura HTTP limitada a 64 KiB, profundidade JSON 16 e prazo do cliente até o fim do corpo. O cliente não segue redirecionamentos e mantém logs sanitizados.

## Continuidade e decisões

Cache protegido próprio: %ProgramData%\SafeUpload\console-policy-cache.json. Seu envelope associa o snapshot operacional a servidor/esquema/porta/contexto, id_host e IP. Cache de outro vínculo não é aplicado nem sobrescrito na recuperação offline. Cache legado separado.

A inicialização lê cache antes da rede; sem cache compatível utiliza a política operacional local. Reutiliza atualização em segundo plano e observações de comunicação existentes. Falha de persistência continua distinguida de recebimento em memória.

A numeração local pode coincidir com idPolitica, por exemplo ambos 1. Uma chave do conteúdo efetivo em memória impede reutilizar veredito ou aprovação staged anterior somente porque o inteiro coincide. Não altera JSON de auditoria, notificações ou protocolo do driver.

Mesmo idPolitica com conteúdo operacional diferente é recusado. Alterar a base operacional local depois de aceitar uma publicação requer nova publicação/revisão para aceitar a nova composição, evitando mudar silenciosamente o significado de uma revisão.

## Validação e limites

- Build Release final de serviço/testes: zero erros/avisos.
- 252 testes selecionados de política, configuração, comunicação, inspeção e cache aprovados.
- 160 execuções adicionais de publicação/canais aprovadas. Há sobreposição dos filtros: 328 casos distintos, não 412 casos diferentes.
- Casos novos: consulta/destino, quatro regras, políticas A/B mudando veredito do mesmo arquivo, nova instância offline, documentos inválidos/regressivos, cache de outro vínculo e colisão de revisão local/central.
- TRX e relatório da sessão em outputs/politica-console-20261030, fora do código do produto.

HTTP controlado por handlers em memória com resposta do contrato publicado. Não houve publicação pela tela Angular, novo ensaio Java/MySQL, instalação SCM/SYSTEM, driver, bloqueio real, homologação de pacote ou CI remoto. Publicação também foi testada como componente isolado, não como qualificação do par do Vitor.

Identidade persistente não é autenticação do dispositivo. Seleção por IP, mudança de IP/interfaces, vínculo endpointId/id_host da auditoria e exibição no painel mantêm dependências próprias.

## Próximo aceite

1. Comparar a entrega do Pedro e escolher uma implementação de consumo em composição identificada.
2. Publicar A pelo painel/backend e conferir aplicação no host correto; publicar B e observar mudança.
3. Rejeitar política inválida preservando a última válida; reiniciar offline e conferir identidade/cache.
4. Conferir evento e reenvio sem duplicação; qualificar proteção real com o par do Vitor e exibição no painel.

Manter candidata local até comparar com Pedro. Os testes isolados não autorizam merge ou instalação como produto.
