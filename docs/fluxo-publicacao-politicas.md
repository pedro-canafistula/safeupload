# Fluxo atual de publicação e consulta de políticas

Este documento descreve o fluxo implementado para publicar uma política pela tela e consultar a última política salva para uma máquina pelo Postman.

## Visão geral

1. O formulário valida nome, IPv4 e pelo menos uma regra.
2. Ao clicar em **Enviar política**, o frontend envia o JSON para `POST /api/politicas`.
3. O proxy de desenvolvimento remove o prefixo `/api` e encaminha a chamada para `POST /politicas` no backend.
4. O backend localiza a máquina em `app.hosts` pelo IP, converte as regras selecionadas para os campos da entidade `regras` e salva a política associada ao host.
5. Depois da resposta `201 Created`, a tela exibe a confirmação e mantém a opção de baixar uma cópia do JSON.
6. O Postman pode consultar a política mais recente daquele IP por `GET /agent/api/policy?ip=...`.

## Publicar pela interface

Na tela **Publicar política**, informe um nome, um IPv4 cadastrado no banco, uma ação e uma ou mais regras. O IP precisa existir em `app.hosts`; um IPv4 válido que ainda não esteja cadastrado não é suficiente.

O corpo enviado atualmente tem este formato:

```json
{
  "versao": "1.0",
  "nome": "Proteção Financeira",
  "destino": {
    "ip": "192.0.2.10"
  },
  "acao": "bloquear",
  "regras": [
    { "tipo": "cpf", "nome": "CPF" },
    { "tipo": "cnpj", "nome": "CNPJ" },
    { "tipo": "credenciais", "nome": "Credenciais e segredos" }
  ],
  "criadaEm": "2026-10-29T16:00:00.000Z",
  "origem": "console-administrativo"
}
```

`192.0.2.10` é um endereço reservado para documentação/testes. Para testar a publicação, ele precisa primeiro estar cadastrado na tabela `app.hosts`.

### Resposta de sucesso

O backend responde com HTTP `201 Created` e uma mensagem semelhante a:

```json
{
  "status": "CREATED",
  "mensagem": "Política salva com sucesso."
}
```

Se o host não for encontrado, a publicação é recusada e a resposta contém a mensagem `Nenhum host cadastrado com o IP: ...`.

## Consultar no Postman

Após publicar, crie uma requisição **GET**, sem corpo, para:

```text
http://localhost:8080/agent/api/policy?ip=192.0.2.10
```

O backend retorna a política mais recente salva para aquele IP, ordenada pelo identificador da política. O retorno inclui `idPolitica`, `versao`, `nome`, `destino` (ID e IP do host), `acao`, `regras`, `criadaEm` e `origem`. Se não existir política para o IP, a rota retorna HTTP `404 Not Found`.

Exemplo abreviado de resposta:

```json
{
  "idPolitica": 1,
  "versao": "1.0",
  "nome": "Proteção Financeira",
  "destino": {
    "idHost": 1,
    "ip": "192.0.2.10"
  },
  "acao": "bloquear",
  "regras": [
    { "tipo": "cpf", "nome": "CPF" },
    { "tipo": "cnpj", "nome": "CNPJ" }
  ],
  "origem": "console-administrativo"
}
```

## Limitações atuais

- A consulta GET comprova que a política foi salva e pode ser lida pelo backend; não comprova que um agente real a consultou, recebeu ou aplicou.
- Ainda não há confirmação/acknowledgment do agente nem estado de entrega na interface.
- O formulário e o armazenamento atual não incluem o bloco `clipboard` nem os campos operacionais do JSON de configuração do agente (por exemplo, escopos, limite de arquivo e timeout).
- A rota GET retorna o formato da política atualmente persistido; ela ainda não gera o JSON operacional completo do agente.
