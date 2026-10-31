# Logs operacionais do agente — candidata privada

Incremento sobre 3d06d276, restrito ao registro de diagnóstico do serviço e suas pontes. A inspeção, o veredito, os destinos operacionais, a auditoria persistida, o IPC e o protocolo do driver não mudam.

## Proteção

OperationalLog recebe templates constantes do código e prepara os argumentos antes de chamar o logger. Exceção, Message, StackTrace, Data e objetos internos não são encaminhados ao provedor. Registra classificação fechada, HRESULT do erro e, quando presentes, código nativo e status HTTP encontrados em até oito causas. A falha preserva o nível e usa EventId 3301/AgentOperationalFailure; IDs de requisição/transferência permanecem tipados. A saída de falha do seed de boot usa a mesma descrição sanitizada.

Campos de arquivo/caminho e argumentos com formato de caminho são omitidos. Endereço HTTP(S) conserva somente esquema, host e porta, sem credenciais, path, query ou fragmento; demais URIs são omitidas. Demais textos passam pelos validadores de privacidade existentes, com teto de leitura. Objetos sem tipo diagnóstico permitido não têm ToString executado: são omitidos. Template/quantidade de argumentos incompatível resulta em mensagem fixa sem os argumentos. Métodos HTTP fora da lista conhecida são omitidos apenas do log, sem mudar o pedido.

Contagens, política, fase/status, tempos, códigos, sessão e IDs continuam disponíveis. Thumbprint hexadecimal válido da CA é identificador público preservado. O log de inspeção FSW inclui o EventId cuja gravação terminou para permitir correlação sem imprimir o nome. Entradas TLS inválidas e caminhos dos aplicativos são substituídos por contagens nas pontes do serviço; não se altera o proxy ou o tratamento de certificados.

## Alcance e limitações

A revisão cobre as chamadas explícitas em Agent.Service: interceptores, publisher staged, IPC/notificações, diagnóstico, inicialização e pontes clipboard/web/TLS. As chamadas Core de Trace já examinadas emitem somente o tipo da falha e não o objeto/corpo. As rotas de comunicação já usam CommunicationLog; métricas da fila já usam eventos com categorias/códigos e permanecem separadas.

Não é filtro global de ILogger nem anonimização universal. Os templates devem ser constantes confiáveis; não passar texto do usuário como template. Logs próprios de frameworks, runtime, Windows, ferramentas e implementações dos colegas (biblioteca Network/kernel) não foram alterados ou qualificados por esta mudança. O aceite instalado deve conferir também essas fontes, inclusive falhas de inicialização do host. Não afirmar que toda saída do processo está coberta. Dados fora dos padrões reconhecidos, quando não pertencem a campos/caminhos omitidos, conservam as limitações do detector.

Sem migração/limpeza de logs históricos, alteração de permissão ou política de auditoria do Windows, instalação de serviço/driver, execução do proxy ou CA, publicação ou novo instalador. O workflow inclui o grupo de testes novos, mas sua preparação não equivale a execução de CI.

## Validação

Testes inspecionam mensagem, estado estruturado e exceção recebidos pelo logger. Cobrem objeto/exception com ToString/Message que falham, dados internos, caminhos sem valor reconhecível, URL com credenciais/query, códigos nativos/HTTP, formatos numéricos, campos tipados, falha de template e nível desativado. Exercitam falha de gravação do NotificationHub sem entrega e FileSystemWatcher real em diretório temporário, com correlação ao evento da fila. Não são testes do driver, serviço SYSTEM ou sessão WPF.
