# Cancelamento com atividade de leitura observada — 24/10/2026

Atividade #58, parte de #48/#43, PR #49 em rascunho. Fonte `6c2bba11ffaa7acf1dd9805104d9a490ce28f7ef`. Nova ferramenta `agente/tools/QueueScanCancellationProbe` e execução no CI em Debug/Release. Sem ganchos ou inspeção de campos privados da fila, sem alteração em Core/serviço; nenhum Java, Angular, banco, driver, contrato, formato, retenção ou instalador alterado. Sem merge.

## Método

Controlador cria pasta nova e semente regular de aproximadamente 64 MiB, com par sintético pendente/confirmado repetido. Há dois IDs repetidos, de propósito: todas as contagens da semente são **linhas**, não eventos únicos ou perfil representativo de produção. Três cenários por consulta (`integrity` e `preview`), cada um com sua cópia da fila e filho próprio. Processo externo nunca é procurado por nome ou terminado; o controlador só encerra o filho criado por ele se ultrapassar o prazo de segurança.

Filho confere tamanho/SHA-256 e aquece parser/consulta em arquivo pequeno separado. Inicia a consulta real do Core em tarefa e exige conjuntamente: tarefa pendente, conflito de compartilhamento indicando leitor aberto na fila do cenário, e aumento mínimo de **256 KiB** no ReadTransferCount do próprio processo desde o início da operação. Só então cancela o token. Não usa atraso fixo para declarar atividade; se o scan terminar antes da observação, o cenário falha.

Exige OperationCanceledException e estado cancelado da tarefa, sem retorno bem-sucedido/parcial. Depois confere tamanho/hash original, escreve um evento na mesma instância e repete a mesma consulta com sucesso. Contagens devem crescer apenas pela linha nova; reabertura encontra o ID de recuperação. Não há descarte nem promoção de temporários. Recusa a pasta instalada de dados e ancestrais/arquivo reparse; requer 2 GiB livres e Windows.

## Resultado local

Release: **seis cenários aprovados**, fonte final acima. Semente de **67.109.625 bytes / 140.250 linhas**: 70.125 pendentes e 70.125 confirmadas. SHA-256 **48D112FE650782E3E9D3106DA5ABB7E7C7A4EACAE6B5BA4661A92EB5ACEEC0D5**.

| Consulta | Repetições | Aumento observado de leitura do processo | Tempo até observação |
| --- | --- | --- | --- |
| Integridade | 3 | 282.624–417.792 bytes | 16,01–22,53 ms |
| Simulação | 3 | 303.104–331.776 bytes | 16,39–18,75 ms |

Tempos são até observar os sinais, não latência de cancelamento nem garantia de desempenho. Em cada caso, cancelamento conservou o hash/tamanho da semente. Retomada: **140.251 linhas, 70.126 pendentes e 70.125 confirmadas**, com ID novo encontrado depois de reabrir. Simulações completas posteriores contam as 70.125 linhas confirmadas anteriores ao corte explícito 2030-01-01T00:00:00Z, mantendo previewOnly true / deletionSupported false.

## CI e aceite

[CI 40115466589](https://github.com/pedro-canafistula/safeupload/actions/runs/40115466589) da fonte exata aprovado nos três jobs. **Doze cenários do novo ensaio aprovados**, seis em Debug e seis em Release; somados aos seis locais, 18 cenários observados. Artefatos do ensaio baixados e conferidos por tamanho/digest publicados pelo GitHub; agregados e recibos originais preservados. Cada caso foi confrontado com observação pendente/leitor aberto/contador mínimo, cancelamento, hash original e contagens após recuperação.

No CI, mesma escala de 67.109.625 bytes/140.250 linhas. Debug: aumentos de leitura de 274.432–585.728 bytes, observação em 15,39–29,13 ms; Release: 327.680–450.560 bytes, 28,43–37,49 ms. Não são medidas de latência do cancelamento ou velocidade física do disco.

Suíte C#: **838 aprovados, zero falhas e quatro skips em 842**, por configuração. Ferramenta compilada sem warnings/erros em Debug/Release. PS7/PS5.1 **42/42** cada, ambiente **4/4**; controles existentes de interrupção, volume cheio e instalação real aprovados. Não herdar resultado de outra fonte.

[Functional web 40115470040](https://github.com/pedro-canafistula/safeupload/actions/runs/40115470040) reprovado nos três jobs: migração sem bean EmpresaRepository, installed-service com backend encerrado antes de iniciar, agent-contract sem backend iniciado (C# 838/842, quatro skips). Trechos identificados dos logs preservados; nenhum componente web alterado. Não declarar o PR inteiro aprovado.

- [x] Seis cenários locais e doze no CI, com observação antes do cancelamento.
- [x] Hash/tamanho preservados e retomada na mesma instância; ID novo confirmado após reabertura.
- [x] Caminho de dados instalado recusado antes da criação de diretórios, em verificação local separada.
- [x] Compilação e controles existentes aprovados; recibos/digests conferidos, sem publicar filas grandes.
- [x] Limites da observação documentados; #58 concluída neste escopo, #43/#48 permanecem abertas.

## Limites da observação

ReadTransferCount é cumulativo do **processo**, não identifica o arquivo, posição exata nem comprova uma linha completamente parseada. Processo isolado, aquecimento prévio, tarefa pendente e conflito no arquivo reforçam a observação, mas não eliminam essa limitação. Não se afirma offset exato de cancelamento ou latência máxima. O cache do Windows pode atender leituras; contador não equivale a bytes físicos lidos do SSD.

O ensaio cancela explicitamente após os sinais; **não prova o prazo de cinco segundos do pipe durante uma varredura longa**. O teste de prazo com lock ocupado da #57 permanece distinto. Não mede starvation, simultaneidade entre serviços, linha gigantesca, corrupção, energia, durabilidade física, API/recibo durável, dados reais ou dias de carga. SHA-256 aqui compara bytes preservados por consulta sem escrita; hash após recuperação naturalmente muda com append.

Nenhuma nova versão ou homologação do instalador no clone nesta atividade. Manter #48 aberta para os aceites restantes e retenção efetiva desabilitada. [Recibos, logs e hashes](evidencias/cancelamento-varredura-20261024/resumo.json); filas sintéticas permanecem fora do Git.
