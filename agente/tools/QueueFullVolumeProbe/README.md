# Ensaio de volume cheio da fila

Ferramenta de diagnóstico, sem alteração de código de produção. Usa o
`LocalQueueAuditSink`, `MonitoredAuditSink` e `AuditQueueHealth` reais em filas
sintéticas, sem instalar serviço, acessar `%ProgramData%\SafeUpload`, abrir
rede ou carregar driver. O pacote 0.1.11 homologado continua sendo o EXE da
fonte `42e34afd`; um instalador reconstruído por outro commit não herda seu aceite.

Execute somente por `agente/scripts/Test-QueueFullVolume.ps1`. O roteiro recusa
hosts comuns antes de criar arquivos: exige runner GitHub-hosted deste repositório
ou UUID exato do clone, elevação e pasta de laboratório específica. Publicação por
`Publish-Probe.ps1` produz EXE self-contained e manifesto de hashes/fonte.

O roteiro cria uma imagem VHD nova de **64 MiB**, monta-a, confere a associação
imagem/disco, tamanho e flags de disco de boot/sistema antes de particionar e
formatar. Número do disco vem exclusivamente dessa imagem; não há argumento de
disco físico, `clean`, exclusão de partição ou reaproveitamento de imagem.
Confere partição, letra livre, NTFS, rótulo aleatório e GUID do volume. A ferramenta
repete identidade, geometria e marcador antes de preencher/deletar seu filler.
Recusa volume do Windows, caminhos redirecionados e resultados no volume a encher.
O preenchimento escreve bytes reais, é limitado e não usa arquivo esparso/SetLength.

Quatro fases: append de evento/justificativa e confirmação de evento/justificativa.
Cada fase tem fila nova, três eventos e uma justificativa. Exige HRESULT real de
disco cheio, classificação `disk_full`, degradação e log 3101. Confirmações que
falharam devem manter bytes publicados idênticos; append pode deixar cauda
incompleta ou resultado ambíguo, mas o prefixo original deve permanecer idêntico.
Não pressupor que IOException significa ausência de todo o registro tentado.

Remove **somente o filler criado pela própria fase**, libera espaço e tenta nova
gravação ou repete a confirmação original. Exige retomada, log 3102 e contador de
falhas preservado; confere metadados/IDs originais após reabrir a fila. Não recupera
automaticamente a tentativa de append falha. Diagnóstico de integridade pode
continuar exigindo atenção se houver cauda inválida; saúde de operações retomada
não é reparo de corrupção. Registra temporários sem limpá-los/promovê-los.

Resultados e logs ficam **fora** do volume de teste. A imagem é desmontada em
`finally` e sua ausência de montagem é conferida; VHD e filas sintéticas ficam
retidos localmente para investigação, fora dos artifacts/Git. Não é prova de
perda de energia, persistência física, serviço SCM/SYSTEM/pipe instalado, API,
driver, disco do sistema cheio, retenção, segurança contra troca concorrente
hostil de caminhos ou operação por vários dias.

Referência de comandos do Windows:
[DiskPart](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskpart)
e [attach vdisk](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/attach-vdisk).
