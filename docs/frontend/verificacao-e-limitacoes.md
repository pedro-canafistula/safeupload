# Verificação e limitações

## Escopo da primeira refatoração

Data: 16/09/2026. Base: ZIP confirmado pelo usuário, com SHA-256 `239de4705cb6e56282bae2174494fa3ed1c93888408f677535fce1a5d0874d35`.

Mudança: centralização do documento HTML, herança do layout administrativo, extração da sidebar e adaptação do bloco do login. Rotas, CSS e dados demonstrativos não foram alterados.

## Método

1. Renderizar as oito rotas reais por FastAPI/Starlette TestClient antes e depois, salvando as respostas HTML e CSS.
2. Verificar HTTP 200 nas páginas e stylesheet, os redirecionamentos da raiz e de `/admin`, o POST do login e o comportamento atual dos quatro formulários de filtro.
3. Abrir as respostas capturadas no Microsoft Edge em modo headless, sem acesso a serviços externos, em viewports de 1440 × 900, 1024 × 900 e 390 × 900, com escala 1.
4. Capturar páginas completas e comparar pixels e a árvore DOM, desconsiderando comentários e espaços de indentação na comparação estrutural. A captura completa pode exceder a largura do viewport quando o layout original transborda.
5. Isolar a correção do fechamento HTML por uma referência de controle: o HTML original, alterando apenas o `</` final para fechamentos válidos de body/html. Essa referência é exclusivamente de verificação e não foi usada para substituir o projeto original.

As respostas HTTP foram exercitadas pela aplicação real via TestClient. As capturas de navegador usam essas respostas locais interceptadas, sem iniciar um servidor de produção. Isso verifica renderização e contratos de resposta, mas não constitui teste completo de implantação ou de fluxo com backend persistente.

## Diferença visual intencional

O layout administrativo original termina com `</`. O navegador interpreta esse trecho como texto visível no corpo, exibindo-o no canto superior direito. Como o body usa Flexbox, esse texto também ocupa largura e comprime a área principal.

A correção remove o texto e libera o espaço indevido. Portanto, as páginas administrativas corrigidas não são pixel a pixel idênticas à versão com erro. A comparação com a referência de controle determina se há diferenças adicionais atribuíveis à reorganização. O login não possuía esse erro.

Os resultados detalhados da comparação ficam em [validacao-layouts.json](validacao-layouts.json), gerado após a execução das verificações. O registro inclui ambiente, dimensões e resultados por captura.

## Resultados obtidos

- Oito páginas e o CSS responderam com HTTP 200, antes e depois.
- Redirecionamentos da raiz e de `/admin` permaneceram HTTP 307; o POST do login permaneceu HTTP 303, sem cookie de sessão.
- Os quatro formulários de filtro continuaram retornando o mesmo conteúdo independentemente dos parâmetros, conforme o comportamento original.
- Nas 24 combinações de página/largura, os pixels e o DOM normalizado foram idênticos à referência com apenas o fechamento HTML corrigido.
- Em relação ao DOM original sem correção, a única diferença normalizada foi a remoção do texto solto `</` nas sete páginas administrativas. O login permaneceu equivalente ao original.
- O conteúdo do CSS permaneceu idêntico byte a byte.
- Foi realizada inspeção visual do dashboard antes/depois e de uma visão conjunta das oito páginas a 1440px; a comparação automatizada cobriu todas as capturas nas três larguras.

## Ambiente

- Python 3.12 do runtime de trabalho.
- FastAPI 0.141.1; Starlette 1.6.0; Jinja2 3.1.6.
- Uvicorn 0.53.0; HTTPX 0.28.1 para o cliente de teste.
- Microsoft Edge 153.0.4234.32, headless, idioma pt-BR e escala 1.

As dependências foram instaladas em uma pasta isolada de trabalho; `requirements.txt` foi preservado. O ambiente emitiu um aviso de depreciação sobre o uso de HTTPX no TestClient, sem impedir os testes. Não foram modificadas as dependências do projeto para eliminar esse aviso da ferramenta de verificação.

## Verificação da refatoração dos templates

Na etapa seguinte foram adicionadas as macros de ícones e avisos e os SVGs das categorias foram retirados das rotas Python. Não houve alteração no CSS, nas URLs, nos textos, nos valores demonstrativos ou nas ações dos controles.

A verificação desta parte recompilou o pacote Python e carregou todos os templates pela `Environment` do Jinja2. Em seguida, a versão anterior e a versão refatorada foram executadas separadamente por FastAPI TestClient com os mesmos dados:

- as oito páginas responderam HTTP 200 nas duas versões;
- `/` e `/admin` permaneceram HTTP 307 para os mesmos destinos;
- `POST /admin/login` permaneceu HTTP 303 para `/admin/dashboard`;
- as oito respostas HTML foram analisadas como árvore DOM, com normalização apenas de espaços de indentação, e permaneceram estruturalmente equivalentes antes/depois;
- conteúdo, atributos, classes e SVGs renderizados permaneceram equivalentes;
- `|safe` deixou de ser usado para categorias porque o contexto agora fornece apenas uma chave de ícone conhecida.

Como o DOM renderizado permaneceu equivalente e o CSS não foi alterado, não há mudança visual esperada nesta etapa. A rodada completa de navegador em múltiplas larguras será repetida no fechamento F06, depois das demais refatorações.

## Verificação da organização do CSS

Na F04, o antigo `static/css/styles.css` de 1.500 linhas foi dividido em sete arquivos por responsabilidade, mantendo `styles.css` como ponto de entrada por `@import`. Nenhuma classe, seletor, declaração ou valor foi intencionalmente alterado.

A verificação desta parte confirmou:

- os sete arquivos especializados concatenados na ordem dos imports reproduzem exatamente, byte a byte, os 40.783 bytes do CSS anterior;
- `styles.css` contém apenas os sete imports, na mesma ordem em que os trechos existiam no arquivo monolítico;
- `tinycss2` analisou `styles.css` e os sete arquivos importados sem erros de parsing;
- as oito páginas continuaram respondendo HTTP 200 por FastAPI TestClient;
- `/` e `/admin` permaneceram HTTP 307 para os mesmos destinos;
- `POST /admin/login` permaneceu HTTP 303 para `/admin/dashboard`;
- `styles.css` e cada um dos sete arquivos importados responderam HTTP 200 com `text/css`;
- templates, rotas, dados demonstrativos e HTML não foram modificados nesta etapa.

A equivalência byte a byte do conteúdo efetivo das regras e a preservação da ordem da cascata indicam que o resultado estilístico esperado é o mesmo. A rodada completa de capturas em navegador e múltiplas larguras continua reservada para a F06, quando todas as refatorações estruturais estiverem concluídas. Os resultados técnicos desta etapa ficam em [validacao-css.json](validacao-css.json).

## Limitações preservadas

- Dados estáticos, sem inspeção, banco ou autenticação.
- Login sempre redireciona ao painel e Sair apenas volta à tela de login.
- Filtros enviam parâmetros, mas as rotas os ignoram.
- Exportação, paginação, cadastro, edição, atualização de políticas e desativação são controles demonstrativos.
- Toggles de categorias mudam apenas localmente; não gravam nem validam uma categoria mínima.
- Indicações de proteção, servidor operacional, PBKDF2 e HMAC são conteúdo de demonstração, não comprovação dessas capacidades.
- Layouts estreitos continuam com limitações de adaptação. A comparação a 390px não certifica responsividade.
- Não houve auditoria de acessibilidade nem validação em Chrome e Firefox nesta etapa.
- Os estados e campos adicionais previstos pelos documentos acadêmicos não foram implementados.

## Verificação da organização do suporte às páginas

Na F05, os dicionários demonstrativos foram retirados de `routes/admin.py` e movidos para `presentation/demo/admin_data.py`. Foram criados sete builders de contexto, um para cada página com dados. O login permaneceu sem builder. Nenhum template, stylesheet, URL, método HTTP ou comportamento demonstrativo foi alterado nesta etapa.

A verificação desta parte confirmou:

- `routes/admin.py` foi reduzido de 549 para 193 linhas e passou a concentrar o fluxo HTTP e a seleção dos templates;
- `demo/admin_data.py` contém os mesmos sete contextos demonstrativos que estavam nas rotas;
- cada contexto novo foi comparado por igualdade estrutural com o literal correspondente da versão anterior;
- cada builder cria uma nova estrutura a cada chamada, sem reutilizar o dicionário retornado anteriormente;
- as oito respostas HTML, incluindo requisições com parâmetros de filtro, permaneceram idênticas byte a byte à etapa anterior;
- `/` e `/admin` permaneceram HTTP 307 para os mesmos destinos;
- `POST /admin/login` permaneceu HTTP 303 para `/admin/dashboard`;
- os módulos Python alterados compilam sem erro;
- filtros continuam ignorados, dados continuam estáticos e nenhuma ação demonstrativa ganhou persistência ou regra nova.

Os resultados técnicos desta etapa ficam em [validacao-suporte-paginas.json](validacao-suporte-paginas.json).

## Continuidade

As refatorações estruturais F03, F04 e F05 estão concluídas. A próxima etapa é a F06: repetir a validação integrada das oito páginas, navegação, formulários e apresentação em navegador, seguida da consolidação final da documentação. As limitações funcionais permanecem preservadas.
