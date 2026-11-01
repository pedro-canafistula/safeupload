# Validação da integração em VM

## Estado

Em 13/10/2026, a primeira etapa passou na VM `SafeUpload-Win10-Lab`, Windows 10 Pro 22H2 build 19045.3803, com a base `e856347c` mais alterações locais: 18 testes Java, 631 testes C# aprovados, quatro ignorados e contrato C# → Java aprovado. O driver não foi instalado. A execução elevada foi necessária para os testes de links simbólicos e proprietário de diretórios.

Em 14/10/2026, a base `612498f9` com alterações locais passou na cópia isolada da VM: 18 testes Java, 661 testes C# aprovados, quatro ignorados, empacotamento Java e contrato C# → Java aprovados. Ver [integração da main](integracao-main-20261014.md). Não existe PR desta entrega e não basta clonar a branch: as alterações ainda não commitadas devem ser levadas junto.

A próxima etapa segue o [plano operacional](VALIDACAO-OPERACIONAL-VM.md), com instalação bloqueada até confirmar o par agente/driver e a build do Windows com o responsável.

## Primeira etapa: testes e contrato, sem instalação do driver

Usar uma VM Windows de desenvolvimento autorizada pela equipe, com PowerShell 7, SDK .NET 10, Java 21, Maven, Git e acesso aos repositórios de dependências. O checkout deve usar um caminho curto, como `C:\SafeUploadLab\repo`, e suportar os caminhos longos já existentes no histórico do driver. Registrar o estado inicial da VM e criar um checkpoint antes da etapa de instalação.

Transferir a versão de trabalho revisada, sem credenciais, bancos de produção ou artefatos locais de build. Conferir o commit e o diff após a transferência. A exclusão local de `driver/scripts/Test-StagedW01Parent.ps1` não é parte da entrega; a ausência deve ser investigada, não propagada como alteração intencional.

Dentro da VM, na raiz do projeto:

```powershell
.\agente\scripts\Test-IntegrationVm.ps1
```

O script executa os testes Java e C#, inicia o backend somente em loopback na porta 18080 com H2 em memória, executa ContractSmoke e encerra o backend. Guarda logs, TRX e `result.json` numa pasta temporária cujo caminho é informado ao final. Para escolher um destino novo para evidências, usar `-ResultsDirectory C:\SafeUploadLab\evidencias\execucao-001`.

Não ativa `SAFEUPLOAD_MACHINE_TESTS`, não instala serviço, driver, CA ou proxy e não altera políticas de proteção. Não reutilizar uma pasta de resultados de execução anterior. Se houver bloqueio de Controle de Aplicativo, registrar o erro e encaminhar ao responsável pelo ambiente; não desativar a proteção como parte do script.

Resultado esperado: testes Java aprovados; testes C# executados (os ignorados devem ser registrados, não confundidos com aprovados); contrato com quatro File, um Clipboard e um Web, Retained e hash publicado preservados, sem duplicar após reenvio. O campo `status: passed` só é gravado quando todas as etapas terminam com sucesso.

O teste de contrato usa dados sintéticos e chama o serviço de clipboard diretamente. Isso valida fila e transporte, mas não uma colagem real na interface Windows. A política Audit usada no smoke pertence apenas à instância de teste; a política do backend continua Off.

## Segunda etapa: integração instalada

Após a primeira etapa passar, alinhar com a equipe o pacote de driver assinado e sua versão correspondente ao agente. Seguir `driver/DEPLOY.md` e `agente/scripts/Install-SafeUploadAgent.ps1`; o instalador exige driver previamente instalado e prepara a política de boot como SYSTEM. Não substituir esse fluxo por comandos isolados de registro do serviço.

Validar na VM com dados sintéticos:

1. Heartbeat identifica a VM e a versão de política correta no painel.
2. Arquivo permitido, bloqueado e transferência retida produzem eventos com UUID e resultado coerentes.
3. Clipboard em Audit produz observações de foco, sem afirmar que houve colagem ou bloqueio. Não deve guardar texto copiado.
4. Backend indisponível: eventos permanecem na fila; restabelecimento e reinício do agente não causam perdas ou duplicação.
5. Reinício do Windows, leitura/gravação/movimentação com aplicativos comuns e arquivo acima do limite.
6. Encerramento e recuperação documentados, com evidências por cenário.

Esta etapa requer acesso à VM, pacote do driver e definição de configuração da política. Não foi executada no host de desenvolvimento. Não há instalação ou mudança de proteção implícita no script da primeira etapa.

## Referências de ambiente encontradas

`driver/scripts/debuggees.txt` registra os domínios libvirt `win10-debug`, `win10-debug2`, `win10-debug3` e `win10-debug4`, nos endereços privados `192.168.122.51` a `192.168.122.54`. `driver/scripts/remote_ps.py` referencia um builder em `192.168.122.210` e uma chave no ambiente Linux de `victor`; não foi acessada nenhuma chave ou VM.

O registro `driver/evidence/2026-10-08/manual-test-win10-debug/README.md` descreve acesso por console virt-manager/SPICE. Os endereços são referências do laboratório, não comprovação de conectividade a partir da máquina de Lucas. Confirmar com o responsável pelo driver qual VM pode ser reservada, forma de acesso, checkpoint e pacote assinado atual antes de enviar arquivos ou iniciar testes.
