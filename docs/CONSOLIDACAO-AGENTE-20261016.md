# Consolidação do agente Windows e da auditoria — 16/10/2026

Base revisada: `origin/main` em `22369257ca7d92d51f8c7ad39c674f67c7198639`.
Inclui a integração anterior `76d4904e` e os três commits de confiabilidade
preparados a partir de `894feb82`, além dos ajustes descritos aqui.

## Comportamento final

- A última política remota válida é persistida com o mesmo limite de confiança
  de ACL da política local. Arquivo sem proteção é recusado, sem reparo silencioso.
- O serviço recupera primeiro o cache protegido ou o padrão existente. Conclui
  uma carga remota inicial limitada pelo timeout antes de iniciar os interceptores,
  que configuram seus escopos no startup. Depois renova em fundo a cada 30 segundos. Inspeções
  usam um snapshot validado durante atualizações, timeout e indisponibilidade.
- Políticas com versão não positiva, nenhuma categoria reconhecida ou parâmetros
  inválidos não substituem a última válida. Categorias numéricas não viram
  categorias desconhecidas que produziriam uma inspeção falsamente limpa.
- A fila JSONL preserva eventos, justificativas, campos adicionais e linhas
  desconhecidas ao confirmar envios. Uma última linha incompleta é separada da
  próxima gravação, para não consumir o novo registro.
- O dispatcher envia eventos e justificativas e exige as contagens de confirmação
  do contrato. Falha de heartbeat não impede uma tentativa de enviar auditoria.
- Justificativas recebidas pelo pipe usam o SID verificado da conexão, em vez da
  conta do serviço. As verificações existentes de sessão, evento, prazo e política
  e a ordem “auditar antes de conceder/publicar” foram preservadas.
- A consulta de auditoria retorna justificativas vinculadas aos eventos filtrados.
  A tela as exibe como texto, sem executar HTML, com identidade e data. Uma
  justificativa registra a solicitação de exceção, não a conclusão da transferência.
- Foram registradas as rotas já implementadas de Auditoria, Endpoints e Relatórios
  e seus links no menu. A API administrativa passou a exigir perfil `admin`, além
  de sessão ativa, revalidando o perfil a cada consulta. O primeiro cadastro no
  banco vazio continua seguindo a regra existente de administrador inicial.

O ajuste Java/Angular é restrito à integração e apresentação dos dados do agente
e à correção necessária do acesso às telas. Não altera cadastro, política de
primeiro usuário, autenticação de endpoints ou o código do driver.

## Validação local

| Verificação | Resultado |
| --- | --- |
| Agente da main, antes das mudanças | 648 aprovados, 7 falhas de privilégio, 4 ignorados; 659 casos |
| Agente consolidado | 683 aprovados, as mesmas 7 falhas, 4 ignorados; 694 casos |
| Comparação dos testes que falharam | Nomes idênticos na main e na consolidação; nenhuma falha adicional |
| Testes direcionados de política, fila, dispatcher e justificativas | 79 aprovados |
| Backend Java 21 | 20 testes aprovados, incluindo H2 persistente após reinício e autorização administrativa |
| Frontend Angular | Build aprovado |
| Navegador Chromium/Playwright | 22 testes aprovados, incluindo integração Java real, justificativas, reenvio, filtros, texto literal e permissões |
| Contrato C# → Java/H2 isolado | Aprovado: File, Clipboard, Web, Retained, hash, heartbeat, política em fundo, fila e justificativa consultável |
| Demonstração com queda real do backend | Aprovada: reinício offline, cache recuperado, registros preservados e confirmados na reconexão |

Os testes C# usaram SDK 10.0.402 e `SAFEUPLOAD_MACHINE_TESTS=0`. A main e a
consolidação foram testadas no mesmo host, com arquivos separados. As sete
falhas envolvem criação de symlinks (cinco casos) e atribuição de proprietário
em hand-back (dois casos). Não foram alteradas as verificações de segurança
para fazê-las passar. Os testes novos passaram, inclusive a recusa de um cache
com ACL não confiável sem modificar suas permissões.

Evidências na cópia de validação: `artifacts/tests/main-baseline.trx`,
`artifacts/tests/agent-reviewed-final.trx`,
`artifacts/tests/consolidation-targeted-final.trx`, `artifacts/backend-final-tests.log`,
`artifacts/frontend-tests-verified.log`, `artifacts/contract-final.log` e
`artifacts/demo-consolidated.log`. Arquivos de build e dependências não integram
os commits. O workflow registra resultados TRX do agente e desativa explicitamente
os testes que alteram a máquina.

## Demonstração

Na raiz do repositório, depois de compilar o backend:

```powershell
& .\agente\scripts\Show-ReliabilityDemo.ps1 -Video
```

Roteiro completo: [agente/RELIABILITY-DEMO.md](../agente/RELIABILITY-DEMO.md).
O evento é sintético; política, persistência, processos separados, falha de
conexão e envio ao Java são reais. A demonstração não instala driver, serviço,
certificado ou regra de rede e mantém as evidências em uma pasta temporária nova.

## Limites e preservação

- A homologação do serviço instalado e da ACL privilegiada continua exigindo VM
  Windows apropriada. A validação local não homologa o driver nem o produto inteiro.
- A aplicação de mudanças de escopo ao gatilho já ativo exige validação específica;
  esta entrega preserva a configuração inicial e não muda o protocolo do driver.
- A política publicada pelo backend continua fixa; não foi criado um editor de
  políticas persistente nesta entrega.
- A autenticação individual do endpoint e o provisionamento seguro continuam
  pendentes no contrato existente. A demonstração usa apenas loopback e H2 isolado.
- A fila continua com um único escritor e sem rotação/criptografia adicionadas.
  Uma falha física de energia não foi simulada.
- A idempotência das justificativas é por evento. Um novo conteúdo com o mesmo
  identificador gera conflito; múltiplas justificativas independentes exigiriam
  uma evolução explícita desse contrato.
- O worktree original, a branch de integração e seus stashes foram preservados.
  A exclusão preexistente de `driver/scripts/Test-StagedW01Parent.ps1` não entra
  nos commits. Sua causa não foi determinada, e o script não foi executado.
- Nenhum arquivo de `sources/`, artefato de build ou dependência foi incluído.
