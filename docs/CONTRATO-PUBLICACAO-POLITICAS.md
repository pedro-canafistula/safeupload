# Publicação de políticas: console → backend → agente

## Fluxo do protótipo

1. O agente registra `endpointId` por `POST /agent/heartbeat`.
2. Um administrador autenticado abre **Políticas**, seleciona esse computador e publica.
3. `POST /api/politicas` valida o documento inteiro, traduz as regras e salva a última política desse computador no banco configurado.
4. `GET /agent/policy?endpointId=...` entrega a política no contrato C# existente.
5. O serviço consulta em segundo plano a cada 30 segundos, valida e atualiza seu snapshot e cache protegido.
6. O heartbeat seguinte informa a versão carregada. Essa informação não é uma confirmação de aplicação no kernel.

`GET /api/politicas` lista a última publicação de cada computador e exige administrador, assim como o POST. Não há histórico de todas as revisões nesta entrega. O nome e a data de publicação são persistidos; o servidor gera a data e o número da revisão.

## Documento do console

```json
{
  "versao": "1.0",
  "nome": "Proteção financeira",
  "destino": { "endpointId": "PC-FINANCEIRO" },
  "acao": "bloquear",
  "regras": [
    { "tipo": "cpf", "nome": "CPF" },
    { "tipo": "cnpj", "nome": "CNPJ" },
    { "tipo": "cartao_credito", "nome": "Número de cartão" },
    { "tipo": "credenciais", "nome": "Credenciais e segredos" }
  ],
  "criadaEm": "2026-10-16T17:39:37.123Z",
  "origem": "console-administrativo"
}
```

Diferenças em relação ao JSON inicialmente enviado pelo console:

- `destino.ip` foi substituído por `destino.endpointId`. O inventário atual não registra IP nem tem vínculo confiável IP → agente. O servidor rejeita destino com IP, inclusive se também houver endpointId.
- `versao: "1.0"` identifica o **esquema do console**. A revisão da política entregue ao agente é um inteiro gerado pelo servidor: padrão v1, primeira publicação v2, próxima v3, por computador. Publicações simultâneas usam bloqueio transacional da linha do computador para não repetir revisões.
- `criadaEm` é opcional e não determina a data oficial: o servidor usa seu próprio relógio.
- `cpf → Cpf`, `cnpj → Cnpj`, `cartao_credito → PaymentCard`, `credenciais → Password + Secret`.
- Regras desconhecidas, duplicadas, vazias ou não implementadas produzem HTTP 400. Nenhuma parte da publicação é aplicada em caso de erro.
- RG, dados bancários, saúde, dados pessoais e documentos confidenciais estão indisponíveis no painel. Seus detectores ainda precisam ser implementados e validados.
- Apenas `acao: "bloquear"` é publicada. `alertar` é rejeitada: não foi homologada de ponta a ponta nos fluxos de arquivos e driver. O campo `auditOnly` no contrato técnico não comprova suporte completo desse fluxo.

Os escopos e demais parâmetros permanecem os do protótipo anterior: extensões `.txt`, `.csv`, `.docx`, `.xlsx`, `.pdf`; pasta `C:\SafeUpload\Escopo Monitorado`; destinos removíveis e de rede; 20 MB; timeout de inspeção de 5 segundos; fail-open; processos excluídos existentes; clipboard desativado; exceção manual desativada. O publicador não altera esses parâmetros nem aceita configurá-los pelo documento do console.

## Limites da confirmação

**Publicada** significa que o servidor salvou a política e pode entregá-la. **Versão informada** é a revisão reportada pelo agente no último heartbeat. O driver recebe a configuração ao iniciar; esta entrega não adiciona uma troca automática e homologada de configuração no kernel. Para um ensaio com driver, reinicie o serviço na VM de teste após publicar e valide o comportamento real. Não use apenas a versão informada para concluir que o driver aplicou a revisão.

O endpoint de leitura e o heartbeat mantêm o modelo de autenticação existente do protótipo. Provisionamento, identidade individual autenticada dos agentes, assinatura de política, histórico de publicação e homologação em aplicações reais continuam pendentes. Não publique esse backend diretamente na Internet.

## Evidências automatizadas

- Java/H2: publicação e tradução, isolamento por computador, revisão monotônica concorrente, rejeição integral, autorização e recuperação após reinício do backend.
- Navegador: publicação real no backend, sucesso somente após resposta, regras indisponíveis e falha sem falso sucesso.
- Cliente C# real: recebe a revisão publicada pelo contrato do console, atualiza seu snapshot em segundo plano, recupera do disco após novo cliente e aplica a categoria no motor de inspeção de um arquivo sintético. Não instala driver.
