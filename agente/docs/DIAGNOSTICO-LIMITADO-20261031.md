# Diagnóstico com prazo total e resposta limitada — 31/10/2026

O cliente administrativo podia conectar ao serviço e ficar indefinidamente em Flush/ReadLine. TimeoutSeconds limitava apenas Connect. A resposta era acumulada sem limite e um JSON encerrado por EOF podia ser aceito como mensagem completa.

Get-SafeUploadDiagnostics.ps1 agora usa um único relógio monotônico, desde antes da consulta, para conexão, envio e leitura assíncronos. TimeoutSeconds aceita 1–300 segundos (padrão 10). Todas as páginas deny-ring compartilham o orçamento; ele não se renova com cada conexão ou fragmento recebido. O finally fecha o pipe inclusive em timeout. Falhas de transporte e expiração têm mensagens fixas, independentes do idioma do runtime.

Cada resposta admite até 1 MiB antes do LF. Lê blocos de até 4096 bytes, recusa o primeiro byte excedente e só interpreta JSON depois do frame completo. UTF-8 inválido, EOF antes do LF, JSON/envelope inválido e resposta para outra consulta são recusados. CRLF e caracteres UTF-8 divididos entre leituras continuam aceitos. O envelope exige ok booleano e data no sucesso ou error textual na falha. Erros retornados pelo serviço conservam a mensagem existente.

As sequências deny-ring precisam avançar estritamente, evitando repetir indefinidamente a mesma página. Páginas completas anteriores podem já ter saído no pipeline quando uma página posterior falha: o erro não representa um inventário completo. Não há alteração de consulta HTTP, backend, fila, driver ou permissões. O script continua administrativo e usa somente o pipe fixo de diagnóstico.

## Validação

O teste scripts/tests/Test-DiagnosticsClient.ps1 carrega via AST as funções exatas e a seleção de consultas do script de produção e as exercita em pipes sintéticos com nomes únicos, sem instalar/iniciar serviço. Não remove a exigência administrativa do script entregue. A vinculação de parâmetros é exercitada separadamente a partir do ParamBlock original. O workflow do instalador executa o teste em PowerShell 7 e Windows PowerShell 5.1; o smoke já existente também chama o script inteiro instalado, nas duas versões, contra o serviço SYSTEM em runner descartável.

Localmente: 29 cenários aprovados em PowerShell 7.6.5 e 29 em Windows PowerShell 5.1.26100.9711. Incluem frame exato no limite, excesso, UTF-8 fragmentado/inválido, CRLF, servidor silencioso, escrita sem consumidor, fluxo lento, EOF parcial, JSON inválido, erro do serviço, consulta posterior à expiração, paginação completa/repetida e orçamento único entre páginas. O ensaio PowerShell 5.1 precisou executar fora da restrição local, que impedia até uma conexão sintética simples; não houve instalação ou alteração do computador.

Os casos com orçamento de um segundo conferem conclusão dentro de uma tolerância de três segundos; isso não promete precisão de tempo real. A duração não limita o processamento de consumidores externos do pipeline. Não qualifica autenticação do serviço, integração com driver ou aplicação de política. Os resultados identificam o hash do script efetivamente testado.
