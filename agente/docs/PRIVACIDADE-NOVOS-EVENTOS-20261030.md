# Privacidade na criação de novos eventos — 30/10/2026

## Comportamento e compatibilidade

O produtor Web grava apenas origem HTTP(S) no novo evento: esquema, host e porta. Credenciais, caminho, parâmetros e fragmento não entram em `DestinationPath`; endereço inválido ou outro esquema vira vazio. O destino original continua disponível à inspeção em memória, preservando sua avaliação/deduplicação. Nome de arquivo informado por um site continua reduzido ao último componente.

Quando `InspectionService` gera um novo ID para um evento de arquivo, reduz `FileName` ao último componente, aceitando separadores Windows e Unix. Caminhos operacionais, destino de arquivo, conteúdo, veredito, usuário, política, hash e controles de publicação não mudam.

A minimização ocorre antes da gravação e da notificação. O emissor HTTP continua projetando os metadados persistidos sem reescrita. Assim o mesmo ID mantém o mesmo payload canônico na primeira entrega e nos reenvios, inclusive quando o servidor aceitou mas a resposta se perdeu.

IDs explícitos de transferências persistidas podem vir de versões antigas: seu `FileName` é preservado, inclusive ao registrar um resultado após upgrade. Os construtores normais de transferência já usam `Path.GetFileName` do destino. Não se presume que fornecer um ID explícito significa criar uma identidade nova. Registros antigos da fila mantêm seus nomes/destinos, que podem conter dados sensíveis e exigem acesso controlado. Não há migração, troca de ID ou confirmação artificial de conflito.

Isso conclui a redução de diretórios em nomes de novos eventos e de segredos fora da origem de URLs Web. Não representa anonimização geral: nomes de arquivo, host/site, caminhos de arquivo, usuário e justificativas ainda são metadados controlados. O núcleo de inspeção TLS/clipboard, contratos Java/SQL/Angular e driver não são alterados.

## Aceite

Declarado antes dos testes: validar produtores reais, persistência e tráfego, ausência dos segredos sintéticos, preservação de caminhos operacionais, coexistência com eventos/IDs antigos e idempotência no contrato atual. Sem benchmark ou mudança nas regras de detecção.

Local: 94 testes aprovados, zero falhas/ignorados, incluindo sete novos casos (seis destinos Web e um arquivo/identidade explícita). Cobrem IPv6, porta, URL inválida/outro esquema, produtor → fila reaberta → dispatcher e confirmação completa. Controles anteriores de Web/arquivo/reenvio continuam ativos. Build do aceite de contrato Release sem avisos/erros; restauração executada com `NuGetAudit=false` apenas na chamada, sem auditoria online de dependências.

O ensaio C#/Java/MySQL passa a criar dois eventos nos produtores reais, publicá-los com a fila ainda pendente e reenviá-los pelo dispatcher atual. Exige origem/nome minimizados na consulta persistida, oito IDs únicos no conjunto (seis legados + dois novos), ausência do segredo sintético e confirmação local. O resultado remoto deve ser registrado no SHA aprovado do PR antes do merge.

A primeira rodada remota encontrou duas expectativas antigas de URL com caminho, na notificação e no proxy TLS. Ajustadas para exigir a origem e ausência de caminho/parâmetros; controles de dono/sessão, bloqueio sensível, destino sem requisição e envio limpo foram preservados. Falhas e TRX originais mantidos nas evidências locais. Os três casos de notificação e o caso TLS passaram localmente; união final de 98 casos distintos aprovados, zero falhas/ignorados. A nova classe de produtores e o grupo de notificação integram o workflow de recibos. Sem alteração no núcleo TLS.
