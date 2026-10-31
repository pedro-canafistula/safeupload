# Campos livres da auditoria — candidata privada

Incremento sobre a candidata do instalador 8133bf3a, restrito ao agente. Primeiro corrige a correlação: InspectionService devolve em memória o evento cuja gravação terminou para aquela chamada. Os interceptores usam esse evento diretamente, sem procurar os cinco últimos pelo nome. Decisões em cache não conservam evento anterior; falha de gravação não produz falsa confirmação nem altera o veredito. RecordedEvent é ignorado na serialização do resultado e não é recibo do servidor ou garantia de fsync.

## Novos registros

AuditTextPrivacy usa os validadores já existentes de CPF, CNPJ, cartão, senha e segredo, independentemente das categorias ativas da política. Quando encontra ocorrência reconhecida, omite o campo inteiro com rótulo fixo; não tenta reconstruir o texto com substituições parciais. Campos sem ocorrência reconhecida permanecem. Texto acima de 4096 caracteres é omitido antes da varredura. Isso não oferece anonimização universal ou detecção de qualquer segredo.

Aplicação: novos nomes, extensão, processo e destino de auditoria de arquivo/web; processos no registro de clipboard; nova justificativa recebida pelo serviço após autorização. A resolução de formato e os caminhos usados para ler, publicar ou devolver arquivos permanecem operacionais. A interface protege a apresentação de nome/destino/processo dos registros antigos sem regravar a fila; o nome de notificação staged também é protegido. Não muda regras de inspeção, permissões de concessão ou identidade de host/usuário/SID.

## Reenvio e staging

Não sanitizar durante o despacho nem no leitor genérico da fila: um registro antigo pode ter sido aceito pelo servidor e estar pendente por resposta perdida. Seus campos e ID precisam continuar iguais. Novas submissões usam AuditOverride.FromNewSubmission; leitura/reenvio de AuditOverride existente preserva o texto canônico.

Nova alocação staged grava AuditMetadataVersion=1 no journal. Publisher projeta essa marca na operação de auditoria e mantém os caminhos originais para I/O. Reinício preserva a marca; ausência indica registro legado, com metadados anteriores para o ID fixo. Versão de projeção desconhecida no journal é recusada. Não retrocarimbar transferências existentes. Não assumir que uma versão antiga do agente oferece rollback compatível com este novo estado; atualização/downgrade exige sua qualificação própria. Essa marca pertence ao estado do serviço, sem alterar ABI do driver.

## Validação e limite

Reprodução anterior da correlação recebeu evento de outra operação com o mesmo nome. Testes verificam resultado direto, decisão em cache, falha de fila, propriedade ausente no JSON, observador real em pasta temporária, omissão de dados sintéticos, apresentação antiga, reenvio idêntico, journal após reinício e publicação no caminho original. Não instalam serviço/driver nem usam backend real ou WPF aberto.

Este recorte não é revisão completa dos logs técnicos: ainda há chamadas de logger com exceções/caminhos em outros componentes a revisar. Identidades técnicas e caminhos privados de recuperação/journal continuam sob seus controles de acesso, não são anonimizados como campos de auditoria. Não apaga registros históricos, não promete sanitização de dados não reconhecidos nem qualifica o conjunto com driver/console. Candidata sem publicação; integração conserva os aceites compartilhados.
