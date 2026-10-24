# Pacote candidato do agente Windows — 21/10/2026

## Resultado

Foi gerado o instalador **SafeUploadAgent-0.1.3-win-x64-setup.exe**, sem executar instalação, serviço, interface ou driver no computador de trabalho. O candidato contém runtime próprio do serviço e da interface. A consulta de políticas da API continua como dependência da equipe; não foi implementado receptor HTTP ou alterado contrato no agente.

| Dado | Valor |
|---|---|
| Fonte dos binários | `ef1d141d6ecd8d76c25336c9e656a767b3b5cc9b` |
| Estado registrado pelo builder | `sourceDirty=false` |
| Versão | `0.1.3` |
| Plataforma | `win-x64`, self-contained |
| Tamanho do instalador | 84.031.218 bytes |
| SHA-256 | `3F130A6959AD0886E2A4490CD586021019876B425369072EC53FB9DA56BE13B5` |
| Arquivos no manifesto | 724 |
| Inventário incluindo manifesto | 725 arquivos |
| Assinatura do instalador | `NotSigned` — candidato de desenvolvimento |

O compilador Inno Setup 6.7.3 já disponível foi verificado: assinatura válida de Pyrsys B.V. e download com SHA-256 `9C73C3BAE7ED48D44112A0F48E66742C00090BDB5BEF71D9D3C056C66E97B732`, correspondente ao bootstrap versionado. A compilação concluiu com sucesso. A assinatura do compilador não assina o instalador produzido.

Os binários do serviço e UI informam a versão `0.1.3+ef1d141d6ecd8d76c25336c9e656a767b3b5cc9b`. Ambos incluem Microsoft.NETCore.App 10.0.13; a UI inclui também Microsoft.WindowsDesktop.App 10.0.13 e PresentationFramework.dll. Foram conferidos coreclr.dll, hostfxr.dll, hostpolicy.dll, System.Private.CoreLib.dll, executáveis, assemblies, deps/runtimeconfig e arquivos de suporte.

## Nova verificação reproduzível

Foi acrescentado `agente/installer/tests/Test-InstallerArtifact.ps1`. Ele lê a saída do builder e valida:

- Versão, commit exato e fonte limpa registrados nos metadados.
- Hash SHA-256 do EXE e todos os hashes do payload com o validador existente.
- Consistência entre manifesto e resultado do build; ausência de arquivos não listados.
- Runtime win-x64 próprio do serviço/UI, sem declaração de dependência de framework global no runtimeconfig.
- Versão/commit publicados, suporte do setup e licença; ausência de arquivos de driver kernel no manifesto.
- Estado da assinatura do instalador, apresentado separadamente do resultado estático.

Não executa os binários nem realiza alterações de serviço, registro, firewall, proxy ou driver. Um PASS não comprova instalação real, segurança do runtime, funcionamento em máquina sem runtime global, assinatura de distribuição ou proteção ativa.

## Testes desta rodada

| Controle | Resultado |
|---|---|
| Geração do EXE com runtime próprio | Aprovada |
| Validador no artefato real | Aprovado, 724 arquivos de payload com hashes conferidos |
| SHA-256 adulterado em cópia dos metadados | Recusado com exit code 1 e motivo esperado |
| Fonte marcada como modificada em cópia dos metadados | Recusada com exit code 1 e motivo esperado |
| Parsing do novo validador em PowerShell 7.6.5 | Sem erros |
| Contratos existentes do instalador em PowerShell 7.6.5 | 39/39 |
| Contratos existentes em Windows PowerShell 5.1 | 39/39 |

Os controles negativos alteraram somente cópias dos metadados. Instalador, payload e manifesto originais foram preservados. As suítes C# não foram repetidas porque esta rodada acrescenta ferramenta de validação e documentação, sem mudar produto ou testes C#. O checkpoint anterior permanece: 53/53 focados Debug, suíte completa Release com 731 aprovados, sete falhos e quatro ignorados. Essas sete falhas continuam pendentes no ambiente com privilégios adequados; não foram resolvidas pela geração do EXE.

## Proveniência e reprodução

O instalador foi produzido a partir do commit de produto `ef1d141d`. O novo validador e este relatório são alterações posteriores de ferramentas/documentação; não alteram os binários desse candidato. Não atribuir o EXE a um commit posterior só porque a branch avançou com o relatório.

Na raiz do repositório, com checkout limpo do commit desejado e compilador verificado:

```powershell
./agente/installer/Build-AgentInstaller.ps1 -Version 0.1.3 -CompilerPath CAMINHO_ISCC -OutputDirectory CAMINHO_SAIDA
./agente/installer/tests/Test-InstallerArtifact.ps1 -BuildResultPath CAMINHO_SAIDA/build-result.json -ResultsPath CAMINHO_SAIDA/artifact-validation.json
```

Os caminhos do build-result.json identificam o payload local usado na validação. O EXE e seu arquivo .sha256 podem ser transferidos à máquina de homologação. O pacote de evidências inclui manifesto do payload, metadados de build, validação, proveniência do compilador e logs, sem duplicar todos os binários expandidos. O script de validação completo requer o payload do build disponível.

## O que falta do nosso lado

1. **Instalação operacional:** testar este EXE em ambiente descartável, serviço LocalSystem, configuração, reinício, fila/política preservadas e remoção. O `Test-InstallerSmoke.ps1` existente exige runner Windows hospedado e descartável do GitHub; sua proteção não foi removida nem simulada no host local.
2. **Windows 10/11 e UI:** validar conta comum, autostart/bandeja, troca de sessão e máquina sem runtime global instalado. Runtime empacotado não substitui esse ensaio.
3. **Privilégios de testes:** executar os sete controles falhos de symlink/proprietário no ambiente Windows preparado, mantendo as asserções.
4. **Integração agente/driver:** trabalhar sobre o par de commits/artefatos acordado e resolver os conflitos do lado do agente, preservando capacidades/readiness, boot policy e restrições da M2. Não incluir kernel no instalador sem um trabalho próprio da equipe.
5. **Manutenção:** definir e implementar upgrade/repair/rollback, retenção e proteção da fila sem descartar pendências; qualificar cada mudança antes de distribuição.
6. **Distribuição:** obter assinatura Authenticode da equipe e realizar os ensaios de instalação/desinstalação antes de liberar produção.

## Dependências externas preservadas

Consulta/publicação de políticas compatível, identidade/autenticação e ensaio de persistência/deduplicação da API permanecem com a equipe de backend. A disponibilização desse contrato será verificada no repositório quando houver nova versão para integração, sem repetir perguntas sobre sua existência. Qualificação do par de driver depende do responsável pelo driver e do ambiente acordado.

O acesso de escrita ao GitHub continua indisponível nesta sessão; nenhum workflow foi disparado, nenhum PR foi publicado/alterado e nenhum merge foi feito. As novas alterações estão em branch local e patch. A macro permanece aberta.
