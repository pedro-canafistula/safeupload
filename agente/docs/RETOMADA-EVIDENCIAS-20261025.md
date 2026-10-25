# Retomada do agente Windows — 25/10/2026

Base de retomada: PR #49, branch `tarefa/consolidar-base-agente-windows`, commit `ebabe031cdf55ef44fdf0e056bfff1f34d4f8677`. Inventário preparado antes de qualquer novo ensaio. #43–#48 continuam abertas; PR #42 preservado em rascunho. Nenhum merge autorizado.

## Evidências presenciais ainda necessárias

| Frente | Evidência que falta | Pré-requisito e critério de aceite |
| --- | --- | --- |
| #45 — Windows 11 | Identidade do ambiente/pacote; instalação em conta comum e sem runtime global; UI/bandeja, login, reconexão e remoção com dados preservados | Ambiente Windows 11 descartável e pacote escolhido por hash. Recibos brutos, logs, IDs e hashes antes/depois; resultados do Windows 10 não substituem este aceite. |
| #45 — upgrade/repair/rollback | Transição entre versões, reparação e retorno da versão acordada, com preservação de política, pendentes e quarentena | Definir versões, suporte do instalador e recuperação antes de executar. A remoção seguida de instalação já feita não comprova upgrade. Não instalar apenas para repetir o ciclo aprovado. |
| #45 — distribuição assinada | Assinatura/cadeia/editor do pacote entregue e comportamento no ambiente alvo | Pacote assinado pela equipe; registrar hash, validade e resultado no destino. O 0.1.14 aprovado é sem assinatura. |
| #46 — identidade do par M2 | Pacote .sys/.inf/.cat com commit/hash/arquitetura; vínculo entre artefato e driver efetivamente carregado | Equipe do driver disponibiliza pacote correspondente e instruções de assinatura, instalação e rollback. Protocolo 18 e commit de referência no JSON não provam identidade. |
| #46 — coletor e integração real | Wrapper elevado/gravação do recibo na VM, duas consultas reais no pipe, reconexão e inspeção/enforcement em cenários separados | Agente com fonte/hash e composição acordados, conectado ao driver identificado. `diagnostics-only-passed` conserva flags de qualificação falsas; não representa proteção. Não executar a sonda padrão que envia política de teste para obter apenas diagnósticos. |
| #44/#47 — API/painel | Política consultável, heartbeat/autenticação de máquina; evento visível com ID/UTC/host/política originais; persistência e deduplicação | Backend e painel disponibilizados pelos responsáveis. Reenvio após resposta perdida, offline/reinício, 401/403 e recibo parcial sem confirmação indevida. Registrar requisições sanitizadas e recibos; loopback e testes de componente não substituem a API real. |
| #48 — durabilidade | Append comprovadamente em curso no instante da interrupção; cauda parcial; queda de energia e recuperação | Ambiente descartável próprio, fixtures sintéticas e observação da fase atingida. Kill após append concluído e disk_full não provam esses cenários. Não provocar falhas na fila preservada do clone. |
| #48 — operação por dias | Crescimento/backlog, recursos e retomada ao longo de período acordado | Perfil/duração/orçamento acordados e coleta contínua; medição de dois minutos e cache aquecido não equivalem a dias de serviço. Ver roteiro abaixo. |
| Evidência visual | Capturas autênticas de novos cenários que exigirem conferência humana | JPGs idênticos da rodada 0.1.14 foram excluídos. JSON autoral não é captura. Se houver exigência formal de imagem daquela rodada, mantê-la como lacuna histórica; não encenar novamente e atribuir à rodada antiga. |

Logs antigos da troca 0.1.4 → 0.1.5 permanecem indisponíveis (#45). Não é possível recriar retrospectivamente o registro original; uma nova execução teria identidade e aceite próprios.

## Evidências aprovadas que devem ser reutilizadas

- [Windows 10 / 0.1.14](HOMOLOGACAO-WIN10-0114-20261024.md): instalação/724 arquivos, inspeções sintéticas, aviso/quarentena, reconexão preservando UI, início após login, remoção com painel aberto e onze arquivos preservados. Fila final: 23 IDs pendentes, 12.973 bytes, SHA-256 `426F7E2F5E08ED03C4627B567BBB7BD8E072C222CFBBEB61CDCFA706036E0807`. Clone e original desligados; clone sem agente ao término. Não consultar a VM para confirmar novamente esses dados nesta retomada.
- Pacote aceito: fonte `887abf8dd85830e554bd4c190562cd380644df47`, EXE SHA-256 `A8164C0965A03D40A4054D77810C511E192A99E4E083215A8F748800F9D9BACA`. O commit ebabe031 contém preparação posterior e não transfere o aceite do instalador para um rebuild.
- [Volume cheio](VOLUME-CHEIO-FILA-20261023.md), #52: erro real 112 nas quatro operações e retomada já aprovados em CI/Windows 10. O checklist histórico de #48 ainda menciona disco cheio como pendente; usar a entrega mais recente, sem apagar o histórico.
- [Preparação M2](PREPARACAO-PAR-M2-20261024.md), #62: 9/9 contratos em cada PowerShell, 43/43 anteriores em cada versão; CI 40148901756 com 893 aprovados, quatro skips e zero falhas em 897 por configuração. Não repetir os testes nessa retomada. Transporte simulado não qualifica driver/pipe reais.
- [Cancelamento observado](CANCELAMENTO-VARREDURA-20261024.md), #58: seis cenários locais/doze CI já aprovados; não prova prazo do pipe durante varredura nem queda de energia.
- Functional web 40148907061 permanece reprovado por inicialização do backend/EmpresaRepository. Não repetir esse fluxo sem mudança relevante da dependência; não declarar o PR inteiro aprovado.

Fontes de acompanhamento consultadas em 25/10: descrições de #43–#48 e comentários de #43/#44/#46/#48. Os textos históricos de algumas atividades estão defasados; os relatórios e comentários posteriores delimitam o aceite atual.

## Pendências independentes da VM

1. Conferir integridade dos recibos já preservados, sem executar seus scripts. Os manifestos de Windows 10/0.1.14 e preparação M2 contêm 25 arquivos cada. A conferência inicial local encontrou 50/50 tamanhos e hashes iguais.
2. Disponibilizar verificador offline reproduzível e recibo da conferência. Integridade relativa ao manifesto não prova autenticidade externa, completude da coleta ou sucesso de um cenário novo.
3. Preparar perfil de operação prolongada e matriz de decisões de retenção abaixo. Nenhum prazo ou descarte passa a vigorar por esta proposta.
4. Reinspecionar fonte de API/M2 apenas quando houver entrega nova relevante; adaptar somente o agente após contrato acordado. Não abrir listener implícito nem transplantar a branch M2 inteira.

Consulta remota desta retomada pelo conector GitHub: main `efe93cf75aa668f2870c0951b48b3ef2c6332226`, políticas `e8afeb4d84df5a5e14f57c9392438e7eec7073a0` e M2 `e0df8d1c1f889418a133d3ae66a87a6c76a7bd5f`, iguais aos registros anteriores. O acesso Git direto encontrou falha de DNS no sandbox; a leitura pelo conector confirmou as referências. Não foi refeita busca de todos os pacotes privados/externos: a indisponibilidade documentada em 24/10 não prova inexistência de pacote novo fora dessas fontes.

## Entrega offline e reprodução

Entregue [Test-PreservedEvidence.ps1](evidence-tools/Test-PreservedEvidence.ps1): lê os dois manifestos preservados e confere somente arquivos regulares com nomes simples, tamanho e SHA-256; não executa arquivos consultados. Recusa manifesto vazio, duplicatas, travessia de diretório e saída existente. Divergência gera recibo de falha e erro; manifesto malformado não gera recibo de sucesso. O arquivo de saída usa CreateNew. Não é verificação de assinatura/autenticidade nem inventário de arquivos não listados; executar sobre evidências estáveis, sem escritor concorrente. Não cobre todas as corridas de substituição por outro processo.

Resultado final: **50/50 arquivos iguais em PS7 e em PS5.1**, sem falhas de integridade. **Seis cenários novos do verificador passaram em cada versão**: igualdade, adulteração de mesmo tamanho, arquivo ausente, travessia, manifesto vazio/duplicado e preservação de saída existente. Não são reexecuções da suíte do agente ou da homologação aprovada. Recibos finais `*-v2.json` e hashes em [resumo.json](evidencias/retomada-20261025/resumo.json).

Primeiras tentativas preservadas: um caso PS7 falhou ao mover fixture temporária por acesso negado do sandbox; substituído por referência a nome inexistente sem mover arquivo. PS5.1 inicialmente recusou scripts pela política local; as execuções posteriores usam Bypass somente no processo filho. A chamada sem ManifestPath revelou PSScriptRoot vazio na avaliação do parâmetro no PS5.1; a construção dos caminhos foi movida para o corpo. Contratos e auditoria dos 50 arquivos passaram nas duas versões com a fonte final. A tentativa inicial de PS5.1 foi encerrada antes de gerar recibo, sem tratar a ausência como sucesso.

Na raiz do repositório, executar apenas quando houver motivo para conferir a cópia de evidências:

```powershell
# Sem OutputPath, retorna JSON; nenhuma instalação ou elevação necessária.
pwsh -NoProfile -File agente/docs/evidence-tools/Test-PreservedEvidence.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File agente/docs/evidence-tools/Test-PreservedEvidence.ps1

# Contratos da ferramenta nova; usam fixtures sintéticas em pasta temporária única.
pwsh -NoProfile -File agente/docs/evidence-tools/Test-PreservedEvidenceContracts.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File agente/docs/evidence-tools/Test-PreservedEvidenceContracts.ps1
```

Para preservar resultado, usar `-OutputPath` no verificador ou `-ResultsPath` nos contratos apontando para arquivo novo em pasta existente. Conferir exit code e conservar JSON inclusive de falha. Os contratos retêm sua pasta de fixtures para inspeção; não fazem limpeza recursiva. O Bypass não altera política persistente do computador.

Somente documentação e ferramentas offline em `agente/docs/` foram acrescentadas; o filtro existente do workflow do agente exclui essa pasta. Nenhum workflow foi disparado manualmente e nenhuma suíte aprovada foi repetida para validar documentação.

## Roteiro proposto para operação prolongada — #48

Proposta para alinhamento, ainda não executada: 72 horas em ambiente isolado com carga sintética. Registrar taxa/tamanho dos eventos e justificativas, distribuição dos destinos e política/hash utilizados. Não fixar um SLA de produção com os números das medições locais.

| Fase proposta | Estímulo | Evidência de saída |
| --- | --- | --- |
| Baseline | Diretório sintético novo; inventário do build, ambiente, relógio UTC e espaço livre | Hashes de artefatos, manifesto inicial e contagem de IDs/metadados esperados |
| Offline — 24 h | Taxa constante acordada; sem consumidor | Backlog esperado versus observado, bytes lógicos, espaço livre, CPU e memória do serviço |
| Recuperação — 24 h | Reenvio com resposta perdida/503 sintéticos; reinício controlado | Mesmos IDs/metadados, pendentes corretos após reabertura; deduplicação sintética identificada como tal |
| Estabilidade — 24 h | Carga mista acordada e picos limitados | Séries temporais e latências; ausência de perda; contagens finais e hashes dos recibos |

Coletar recursos a cada minuto e diagnósticos de fila a cada quinze minutos como ponto inicial a acordar. Cronometrar as consultas: elas percorrem a fila e podem atrasar escrita. Registrar separadamente atraso de coleta, erro/timeout e resultado incompleto; ausência de amostra não significa zero ou saúde. Não coletar conteúdo de documentos, tokens ou URLs com segredos. Definir limite de parada por espaço livre e duração com os responsáveis antes da execução; ao atingir o limite, interromper a carga e preservar os pendentes, sem limpeza automática.

Aceite exige comparação dos conjuntos de IDs e metadados esperados após reabertura, contagens por tipo/estado, linhas inválidas/desconhecidas, órfãos, degradação/retomada, séries de recursos e descrição de todos os intervalos sem amostra. Recibo parcial, timeout ou backend indisponível mantêm o cenário inconclusivo. Registrar o número efetivo de horas; não declarar 72 h antes da conclusão.

O simulador HTTP continua útil para falhas controladas; o aceite de persistência/deduplicação real pertence a #47. A execução de carga não inclui ensaio de energia nem autoriza instalação automática na VM existente. Não foi criada automação nesta retomada.

## Decisões de retenção e proteção para alinhamento

| Decisão | Situação conhecida | Encaminhamento proposto |
| --- | --- | --- |
| Base temporal | Simulação usa ocorrência; data de confirmação não é persistida | Equipe define se prazo parte da ocorrência ou confirmação. Não inferir data de confirmação pela ocorrência. |
| Pendentes | Entrega pelo menos uma vez; servidor deve deduplicar | Preservar pendentes e referências; orçamento cheio deve sinalizar/limitar carga conforme regra acordada, sem descarte. |
| Confirmados | Confirmação local não prova recibo durável do servidor | Definir contrato de recibo/idempotência e prazo antes de propor remoção. |
| Temporários | Inventário limitado; não prova que arquivo é órfão recuperável | Revisar recuperação, exclusividade e vínculos antes de promover/apagar; manter política atual sem limpeza. |
| Segmentos/checkpoints | Confirmação ainda regrava a fila; custo cresce com tamanho | Preparar desenho/migração e recuperação com falhas por etapa antes de mudar formato. Não implementar pela simples aprovação de um benchmark. |
| Proteção local | ACL administrativa não resolve comprometimento por administrador | Identidade/autenticação e requisito de integridade/criptografia precisam ser acordados; não prometer resistência que os testes não demonstraram. |

Oportunidades de comunicação: pacote/identidade/composição com responsável do driver (#46); API e recibo durável com Thiago (#44/#47); visualização com responsável Angular; assinatura/distribuição e orçamento de carga com a equipe. Nenhuma mensagem enviada por WhatsApp, ClickUp ou comentário nesta retomada.

Nenhum Java, Angular, banco, driver, componente instalado ou arquivo de `sources/` alterado. Nenhum teste aprovado reexecutado, VM ligada, pacote 0.1.14 substituído ou merge realizado.
