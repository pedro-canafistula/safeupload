# Temporários com acesso negado e serviço SYSTEM — 25/10/2026

Continuidade de #48/PR #49, base `4d514102`. Esta entrega acrescenta testes;
nenhum código de produção ou contrato do diagnóstico foi alterado.

## Lacunas e método

A classificação anterior foi exercitada no Core/pipe isolado, mas não por um
serviço instalado LocalSystem. Faltava também provocar uma negação real de
leitura, distinta de sharing violation. O escopo atual fecha apenas essas
lacunas, sem promoção, remoção ou recuperação automática de temporários.

Novo caso xUnit cria candidato sintético, nega somente ReadData ao SID do usuário
do teste e comprova UnauthorizedAccessException em leitura comum. A consulta deve
retornar um unavailableCandidate, zero inUse e zero bytes lidos, Complete=false,
RequiresAttention=true e flags de recuperação falsas. O teste exige DACL idêntica
antes/depois da consulta; restaura somente a DACL original em finally, confere
bytes e repete a classificação com acesso restaurado. Não cria fila publicada.
A restauração exige mesmas regras na mesma ordem (SID, máscara, allow/deny,
herança/propagação), proprietário, grupo e proteção/canonicalidade. A marca
auto-inherited do SDDL pode ser normalizada pelo Windows; os SDDL são registrados,
sem confundir essa normalização com alteração de permissões pelo diagnóstico.

O teste instalado integra o **mesmo ciclo já existente** de instalação/reinício/
remoção do runner GitHub-hosted descartável. Não instala serviço no host nem usa
VM local. Guardas anteriores de ambiente e ausência de estado permanecem ativas.

Para cada consulta nova verificada, GetNamedPipeServerProcessId identifica o
processo da outra ponta do pipe; seu PID deve coincidir com o serviço Running
no SCM, configurado LocalSystem. GetOwnerSid do processo deve devolver S-1-5-18.
O recibo preserva PID do pipe/SCM, conta e SID antes/depois do reinício. Isso
vincula a resposta ao serviço nesta execução; não é atestação contra kernel ou
administrador hostil e não prova identidade de thread sob outro impersonation.

Fixtures de classificação: o temporário sem terminador e a junction já existentes,
mais três cópias estruturais de evento com dispatched=true e um registro futuro.
O evento original publicado permanece pendente. Uma cópia fica aberta com
FileShare.None; outra recebe Deny ReadData explicitamente para S-1-5-18. Exige-se:

| Fase | Resultado esperado |
| --- | --- |
| Compartilhamento + ACL negada | Seis candidatos: um em uso, um indisponível, um estruturalmente completo, um suspeito, um sem terminador e um inseguro |
| Acesso restaurado | Três estruturais, um suspeito, um sem terminador e um inseguro; zero em uso/indisponíveis |
| Reinício | Mesmas classes, bytes lidos e flags; nova correlação do pipe com o processo SYSTEM atual |
| Remoção | Arquivos/bytes e DACL restaurada preservados; nenhum candidato promovido ou apagado |

O teste preserva hashes de todos os candidatos, fila publicada e metadados/IDs
dos eventos. Não exige igualdade de EntriesExamined entre fases: entradas
irrelevantes podem mudar, e diretório não é snapshot transacional. A junction
mantém Complete=false e RequiresAttention=true mesmo depois de restaurar acesso;
nenhuma fase pode ser apresentada como autorização para recuperação.

A fila publicada desse smoke contém a linha inválida e o tipo futuro inseridos
pelos controles anteriores de integridade. Eles permanecem diagnosticáveis;
não se afirma que a fila inteira desse cenário não tinha linhas incompatíveis.
O caso anterior de fila íntegra versus cópia conflitante segue aprovado nos
testes da classificação, sem necessidade de repetir a homologação Windows 10.

## Validação e reprodução

O novo caso de ACL passou localmente em Release e Debug, um teste por configuração.
Nenhum outro teste local aprovado foi repetido sem necessidade. Sintaxe do smoke
PowerShell e compilação do helper nativo de identidade verificadas no host;
o smoke instalado não foi executado no host. A versão final do caso isolado
passou localmente em Debug; Release/Debug finais também foram conferidos no CI.

Primeiro CI, fonte `90bba2f4`: o novo caso de ACL falhou em Debug/Release e o
smoke também parou no oráculo de restauração, comparando SDDL literal `D:` versus
`D:AI`. O oráculo foi corrigido para comparar permissões e sua ordem, proprietário,
grupo e proteção, mantendo comparação literal antes/depois de cada consulta.
Os resultados reprovados e o recibo parcial do serviço foram preservados; essa
tentativa não constitui aceite final da entrega.

Fonte corrigida **`214d20696ffa7f974bbf709b2178ba3c42cdeb68`**.
[CI final 40206370352](https://github.com/pedro-canafistula/safeupload/actions/runs/40206370352):
**três jobs aprovados**, C# **919 aprovados, zero falhas e quatro ignorados em
923 por configuração Debug/Release**. Novo caso de ACL Passed nos dois TRX.
Contratos PS7/PS5.1 **44/44**, ambiente **4/4**. Três ZIPs finais (dois C# e
instalação) verificados por tamanho/digest; três ZIPs da tentativa reprovada
também conferidos e recibos/TRX preservados.

O recibo final do smoke é **passed** em Windows Server 2025 Datacenter,
10.0.26100, runner descartável. Pipe/SCM identificaram PID **6216** antes e
**3196** depois do reinício, ambos com conta LocalSystem e SID **S-1-5-18**.
Contagens com restrições: seis candidatos, um em cada classe esperada. Com
acesso restaurado e após reinício: três estruturais, um suspeito, um sem LF e
uma junction insegura, sem em uso/indisponíveis. Flags de recuperação falsas,
RequiresAttention=true e Complete=false em todas as fases, como esperado.

Quatro candidatos novos preservados por SHA-256, além do temporário/junction
anteriores; fila, IDs/metadados, política e arquivos mantidos até a remoção.
Permissões anteriores/restauradas coincidiram na ordem das regras e atributos
verificados; SDDL literal diferiu pela normalização já registrada. Depois da
consulta e da remoção, a DACL restaurada permaneceu literalmente inalterada.
Não se transferiu esse aceite ao Windows 10/11 ou à VM local.

[Manifesto, TRX, recibos originais e pré-teste de identidade](evidencias/temporarios-system-20261025/resumo.json).
O pré-teste de pipe isolado valida somente a chamada nativa com processo próprio;
seu systemServiceQualified=false não é o recibo do serviço instalado. Os JSONs
de instalação/TRX foram copiados dos ZIPs verificados, sem reserialização.

[Functional web final 40206372720](https://github.com/pedro-canafistula/safeupload/actions/runs/40206372720)
reprovado: migration sem EmpresaRepository, agent-contract com C# aprovado mas
backend não iniciado, installed-service com backend encerrado antes de iniciar.
Excertos dos logs e IDs preservados. Nenhum Java/banco/painel foi editado e
nenhum workflow foi redisparado manualmente. Não declarar PR inteiro aprovado.

Reproduzir o caso isolado em Windows, com acesso para alterar a DACL do próprio
arquivo temporário:

```powershell
dotnet build agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Release
dotnet vstest agente/SafeUpload.Agent.Tests/bin/Release/net10.0-windows/SafeUpload.Agent.Tests.dll '--TestCaseFilter:FullyQualifiedName~ACL_negando_leitura' '--logger:trx;LogFileName=acl-release.trx' --ResultsDirectory:artifacts/acl-release
```

Para o ensaio instalado, o workflow do agente usa Test-InstallerSmoke.ps1 após
build/validação do pacote, em runner descartável sem estado SafeUpload anterior.
Não falsificar variáveis de GitHub para executar esse teste no computador de
trabalho. A ACL é alterada somente no candidato criado pelo ensaio e restaurada
em finally; o agente não corrige permissões por conta própria. Erros conservam
recibo parcial de teste e status de falha, nunca aceite parcial do produto.

- [x] Negação real de ReadData diferenciada de compartilhamento no caso unitário.
- [x] Bytes e permissões preservados; DACL inalterada pela consulta, leitura restabelecida sem mudar a fila.
- [x] Helper nativo e sintaxe PowerShell verificados sem instalação local.
- [x] Conferir execução instalada, identidade do pipe/SYSTEM e invariantes no CI.
- [x] Preservar TRX/recibo do runner e registrar resultado de Functional web.

Sem Java, Angular, banco, driver, fontes sincronizadas ou VM alterados. O pacote
0.1.14 homologado conserva seu aceite próprio; eventual rebuild do CI não o
substitui. PR #42 preservado, PR #49 em rascunho, sem merge. #48 continua aberta
para energia, escrita nativa sem instrumentação, operação prolongada e regras
de retenção/recuperação; esta entrega não muda essas decisões.
