# Histórico autorizado e reconexão — 30/10/2026

## Resultado

A interface deixa de abrir `queue.jsonl` diretamente. Ao conectar, recebe do serviço um retrato de até 500 eventos, limitado a 512 KiB. O serviço identifica a conta pelo token do processo conectado ao pipe; o cliente não informa o nome de usuário. O filtro de conta/computador ocorre antes do limite. A leitura usa uma janela do arquivo capturada sob o bloqueio da fila e percorre essa janela sem manter o bloqueio de escrita.

Eventos de outra conta ou computador não entram no histórico. A exceção explícita são os eventos legados de FileSystemWatcher já difundidos para o computador: canal File, processo desconhecido/zero e escritor SYSTEM/conta da máquina. Esses registros não têm autoria interativa confiável. Não se amplia esse escopo para clipboard, web, driver ou staging. Identidade ausente ou sem nome qualificado recebe histórico indisponível.

O retrato só é enviado à conexão autenticada: não é publicado nem reproduzido no hub para outros assinantes. O registro de emissões guarda apenas o tipo/disponibilidade, sem lista, IDs ou conteúdo dos eventos. A fila privada permanece intacta e sem nova permissão para o aplicativo.

Reconectar substitui as listas, elimina IDs repetidos e não abre alertas antigos. Eventos recebidos ao vivo são deduplicados. Status mantém oito atividades e histórico mantém 500. Desconectar preserva a última lista, identificada como indisponível, em vez de confundir falha com histórico vazio. Comunicação administrativa e `--show` permanecem disponíveis.

Na observação por FileSystemWatcher, a notificação só declara quarentena quando `File.Move` conclui. Arquivo aberto sem compartilhamento de exclusão permanece no lugar; colisões não sobrescrevem arquivos existentes. Falha no registro de log também não muda esse resultado. A tela descreve restrição/inspeção aprovada, sem afirmar que um upload foi enviado ou impedido preventivamente. Isso não qualifica o driver.

## Origem e aceite declarado

Extração seletiva de componentes da branch preservada do #49 (`9680383e`), adaptados à main `3658b449`. Não se importam os servidores, configuração ou composição antigos por inteiro. O recorte pertence à experiência local do agente e não altera Java, SQL, Angular, política do Pedro ou driver.

Critérios: autorização antes do limite, snapshot limitado por quantidade e bytes, conexão/reconexão real, ausência de repetição de alertas, arquivo de auditoria intacto, mensagem de quarentena baseada no resultado real e preservação da comunicação atual.

## Validação

- Recorte final de histórico/quarentena/apresentação: 28 aprovados, zero falhas/ignorados, incluindo pipe real, reconexão, filtragem antes do limite, mensagem excessiva, payload inválido e journal sem eventos privados.
- Recorte anterior de regressão inclui protocolo, hub, journal, leitura limitada e monitoramento. Duas falhas locais antigas de criação de links simbólicos: esta conta não possui o privilégio necessário. Preservadas no TRX; não foram ignoradas nem enfraquecidas.
- Aplicativo WPF Release: compilado, zero avisos/erros. Prévia renderizada nos estados aguardando, conectado e desconectado; último histórico continua visível com aviso.
- O roteiro Windows descartável `Test-HostIdentityBackend.ps1` passa a ler status + histórico autenticado do serviço LocalSystem na primeira inicialização e após reinício offline. Verifica disponibilidade, limite e preservação da fila vazia. O teste unitário de pipe cobre histórico persistido não vazio; a interface renderizada não representa um login real em outra conta.

O aceite remoto deve ser registrado com o SHA e os resultados do PR. Não há qualificação de Windows 11, sessões RDP simultâneas, driver/Word ou novo mecanismo de autenticação de dispositivo neste recorte.
