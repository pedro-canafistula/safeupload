package com.safeupload;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.safeupload.agent.AgentSignature;

/**
 * O fluxo console ↔ agente inteiro, com a aplicação real e o DDL real de db/initdb num MySQL descartável.
 * Rode com SAFEUPLOAD_TEST_MYSQL_URL=jdbc:mysql://127.0.0.1:3306 (o teste APAGA os bancos app e acesso desse servidor).
 */
@EnabledIfEnvironmentVariable(named = "SAFEUPLOAD_TEST_MYSQL_URL", matches = ".+")
@SpringBootTest(classes = SafeuploadApplication.class)
@AutoConfigureMockMvc
class ConsoleAgentFlowTest {
    static final String SERVER = System.getenv("SAFEUPLOAD_TEST_MYSQL_URL");
    static final String USER = System.getenv().getOrDefault("SAFEUPLOAD_TEST_MYSQL_USER", "root");
    static final String PASSWORD = System.getenv().getOrDefault("SAFEUPLOAD_TEST_MYSQL_PASSWORD", "");
    static final String OPTIONS = "?allowPublicKeyRetrieval=true&useSSL=false";

    @DynamicPropertySource
    static void databases(DynamicPropertyRegistry registry) {
        for (String schema : List.of("app", "acesso")) {
            registry.add(schema + ".datasource.url", () -> SERVER + "/" + schema + OPTIONS);
            registry.add(schema + ".datasource.username", () -> USER);
            registry.add(schema + ".datasource.password", () -> PASSWORD);
        }
    }

    @BeforeAll
    static void freshSchema() throws Exception {
        try (var connection = DriverManager.getConnection(SERVER + "/" + OPTIONS, USER, PASSWORD);
             var statement = connection.createStatement()) {
            statement.execute("DROP DATABASE IF EXISTS app");
            statement.execute("DROP DATABASE IF EXISTS acesso");
            for (String file : List.of("01_schema_acesso.sql", "02_schema_app.sql")) {
                String ddl = Files.readString(Path.of("../../db/initdb", file)).replaceAll("(?m)^--.*$", "");
                for (String sql : ddl.split(";\\s*\\n")) if (!sql.isBlank()) statement.execute(sql);
            }
        }
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;

    // ---- utilitários ----

    record Agent(int id, KeyPair keys) {}

    JsonNode body(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    MvcResult call(MockHttpServletRequestBuilder request, Object payload, int expected) throws Exception {
        if (payload != null) request.contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsBytes(payload));
        return mvc.perform(request).andExpect(status().is(expected)).andReturn();
    }

    MockHttpSession login(String email, String password) throws Exception {
        var result = call(post("/auth/login"), Map.of("email", email, "senha", password), 200);
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    static Map<String, Object> address() {
        return Map.of("cep", "70000-000", "logradouro", "Rua A", "numero", 1, "complemento", "", "bairro", "Centro",
            "cidade", "Brasília", "estado", "DF");
    }

    static Map<String, Object> company(String name, String cnpj) {
        return Map.of("razao_social", name, "nome_fantasia", name, "cnpj", cnpj, "email_contato", "c@" + cnpj + ".test",
            "telefone_contato", "61999999999", "endereco", address());
    }

    static Map<String, Object> host(String hostname) {
        return Map.of("hostname", hostname, "ip", "10.0.0.5", "mascara", 24, "sistema_operacional", "Windows 10 Pro",
            "versao_so", "19045", "mac_address", "00:11:22:33:44:55");
    }

    Agent enroll(MockHttpSession admin, String hostname) throws Exception {
        String token = body(call(post("/admin/token").session(admin), null, 200)).get("token").asText();
        var keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var result = call(post("/agent/enroll"), Map.of("token", token,
            "chave_publica", Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()), "host", host(hostname)), 201);
        // Token é de uso único.
        call(post("/agent/enroll"), Map.of("token", token,
            "chave_publica", Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()), "host", host(hostname)), 401);
        return new Agent(body(result).get("id_host").asInt(), keys);
    }

    MockHttpServletRequestBuilder signed(String method, String route, Agent agent, byte[] content, long time) throws Exception {
        return signed(method, route, agent, content, time, UUID.randomUUID().toString());
    }

    MockHttpServletRequestBuilder signed(String method, String route, Agent agent, byte[] content, long time, String nonce)
            throws Exception {
        var signer = Signature.getInstance("Ed25519");
        signer.initSign(agent.keys().getPrivate());
        signer.update(AgentSignature.message(method, route, agent.id(), time, nonce, content).getBytes(StandardCharsets.UTF_8));
        var request = method.equals("GET") ? get("/agent/" + route) : post("/agent/" + route);
        request.header(AgentSignature.HOST, agent.id()).header(AgentSignature.TIME, time).header(AgentSignature.NONCE, nonce)
            .header(AgentSignature.SIGNATURE, Base64.getEncoder().encodeToString(signer.sign()));
        if (content.length > 0) request.contentType(MediaType.APPLICATION_JSON).content(content);
        return request;
    }

    MvcResult agentCall(String method, String route, Agent agent, Object payload, int expected) throws Exception {
        byte[] content = payload == null ? new byte[0] : json.writeValueAsBytes(payload);
        return mvc.perform(signed(method, route, agent, content, Instant.now().getEpochSecond()))
            .andExpect(status().is(expected)).andReturn();
    }

    static Map<String, Object> policyRequest(String name, boolean isDefault, String cpfAction) {
        var categories = new java.util.HashMap<String, String>();
        for (String code : List.of("cpf", "cnpj", "rg", "cartao_credito", "dados_bancarios", "credenciais",
                "dados_saude", "dados_pessoais", "documentos_confidenciais")) categories.put(code, "ignorar");
        categories.put("cpf", cpfAction);
        categories.put("rg", "alertar");
        return Map.of("nome", name, "padrao", isDefault, "configuracao", Map.of(
            "categorias", categories, "pastas", List.of("C:\\Dados\\Financeiro"), "pendrives", true, "rede", true,
            "extensoes", List.of(".txt", ".docx"), "tamanhoMaximoMb", 50, "tempoLimiteSegundos", 600,
            "permitirJustificativa", false, "clipboard", "desligado"));
    }

    static Map<String, Object> event(String endpoint, String verdict) {
        return Map.ofEntries(Map.entry("eventId", UUID.randomUUID().toString()), Map.entry("occurredAtUtc", Instant.now().toString()),
            Map.entry("endpointId", endpoint), Map.entry("userName", "CORP\\maria"), Map.entry("fileName", "=planilha.txt"),
            Map.entry("extension", ".txt"), Map.entry("sizeBytes", 10), Map.entry("verdict", verdict),
            Map.entry("categories", List.of("Cpf")), Map.entry("processName", "notepad.exe"), Map.entry("processId", 42),
            Map.entry("destinationPath", "C:\\Dados\\Financeiro\\planilha.txt"), Map.entry("policyVersion", 1),
            Map.entry("elapsedMs", 3), Map.entry("channel", "File"));
    }

    private Map<String, Object> policyUsing(String name, Map<String, String> rules) {
        var base = new java.util.HashMap<>(policyRequest(name, false, "bloquear"));
        var config = new java.util.HashMap<>((Map<String, Object>) base.get("configuracao"));
        config.put("regrasPersonalizadas", Map.copyOf(rules));
        base.put("configuracao", config);
        return base;
    }

    private static Map<String, Object> ruleWithConditions(String name, List<?> leaves) {
        return Map.of("nome", name, "quando", Map.of("todos", leaves), "exemplos", Map.of(
            "sinalizar", List.of("marca comum"), "naoSinalizar", List.of("texto livre")));
    }

    private void verifyPolicyBudgets(MockHttpSession root) throws Exception {
        var enabled = new java.util.LinkedHashMap<String, String>();
        var leaf = Map.of("contem", List.of("marca comum"));
        for (int i = 1; i <= 20; i++) {
            var rule = ruleWithConditions("Condições " + i, java.util.Collections.nCopies(20, leaf));
            int id = body(call(post("/regras").session(root), rule, 201)).get("id").asInt();
            enabled.put(String.valueOf(id), "bloquear");
        }
        var saved = body(call(post("/politicas").session(root), policyUsing("Limite de condições", enabled), 201));
        int policy = saved.get("id").asInt(), version = saved.get("versao").asInt();
        var extra = ruleWithConditions("Uma condição adicional", List.of(leaf));
        int extraId = body(call(post("/regras").session(root), extra, 201)).get("id").asInt();
        enabled.put(String.valueOf(extraId), "bloquear");
        assertThat(body(call(put("/politicas/" + policy).session(root),
            policyUsing("Limite de condições", enabled), 400)).get("mensagem").asText()).contains("400");
        assertThat(body(call(get("/politicas/" + policy).session(root), null, 200)).get("versao").asInt()).isEqualTo(version);

        var terms = new java.util.ArrayList<String>();
        terms.add("marca comum");
        for (int i = 0; i < 49; i++) terms.add("marca " + "x".repeat(77) + i);
        var oversized = ruleWithConditions("Uma condição adicional", java.util.Collections.nCopies(20, Map.of("contem", terms)));
        var small = body(call(post("/politicas").session(root),
            policyUsing("Limite de bytes", Map.of(String.valueOf(extraId), "alertar")), 201));
        assertThat(body(call(put("/regras/" + extraId).session(root), oversized, 400))
            .get("mensagem").asText()).contains("64 KiB");
        assertThat(body(call(get("/politicas/" + small.get("id").asInt()).session(root), null, 200))
            .get("versao").asInt()).isEqualTo(small.get("versao").asInt());
        assertThat(body(call(get("/regras/" + extraId).session(root), null, 200)).get("revisao").asInt()).isEqualTo(1);

        var standalone = new java.util.HashMap<>(oversized);
        standalone.put("nome", "Regra que ultrapassa o tamanho");
        int large = body(call(post("/regras").session(root), standalone, 201)).get("id").asInt();
        assertThat(body(call(post("/politicas").session(root),
            policyUsing("Publicação excessiva", Map.of(String.valueOf(large), "bloquear")), 400))
            .get("mensagem").asText()).contains("64 KiB");
    }

    @Test
    void consoleAndAgentWorkTogetherInsideOneCompany() throws Exception {
        // Primeiro cadastro: empresa A + root.
        call(post("/auth/firstregister"), Map.of("username", "root", "email", "root@a.test", "cpf", "11111111111",
            "senha", "Senha-forte-1", "nome_completo", "Root A", "data_nascimento", "1990-01-01",
            "empresa", company("Empresa A", "11111111000111"), "endereco", address()), 201);
        var root = login("root@a.test", "Senha-forte-1");

        // Máquina cadastrada por token; sem política atribuída o agente recebe 404.
        var agent = enroll(root, "PC-FIN-01");
        call(get("/agent/identity"), null, 401);
        assertThat(body(agentCall("GET", "identity", agent, null, 200)).get("id_host").asInt()).isEqualTo(agent.id());
        agentCall("POST", "heartbeat", agent, Map.of("host", host("PC-FIN-01"), "versao_agente", "0.2.0"), 200);
        agentCall("GET", "policy", agent, null, 404);

        // Política padrão: o agente recebe o documento nativo.
        int policyId = body(call(post("/politicas").session(root), policyRequest("Padrão", true, "bloquear"), 201)).get("id").asInt();
        var document = body(agentCall("GET", "policy", agent, null, 200));
        int version = document.get("version").asInt();
        assertThat(document.get("activeCategories").toString()).isEqualTo("[\"Cpf\",\"Rg\"]");
        assertThat(document.get("alertCategories").toString()).isEqualTo("[\"Rg\"]");
        assertThat(document.at("/monitoredScopes/destinationPaths/0").asText()).isEqualTo("C:\\Dados\\Financeiro");
        assertThat(document.get("failOpen").asBoolean()).isFalse();

        // Endpoints: esperada ≠ aplicada até o heartbeat relatar a versão.
        var endpoint = body(call(get("/endpoints").session(root), null, 200)).at("/itens/0");
        assertThat(endpoint.at("/politicaEsperada/versao").asInt()).isEqualTo(version);
        assertThat(endpoint.get("politicaDesatualizada").asBoolean()).isTrue();
        agentCall("POST", "heartbeat", agent, Map.of("host", host("PC-FIN-01"), "politica_aplicada", version), 200);
        endpoint = body(call(get("/endpoints").session(root), null, 200)).at("/itens/0");
        assertThat(endpoint.get("politicaDesatualizada").asBoolean()).isFalse();
        assertThat(endpoint.get("status").asText()).isEqualTo("online");

        // Grupo com outra política: o host passa a receber a política do grupo.
        int other = body(call(post("/politicas").session(root), policyRequest("Financeiro", false, "alertar"), 201)).get("id").asInt();
        int group = body(call(post("/grupos").session(root), Map.of("nome", "Financeiro", "politicaId", other), 201)).get("id").asInt();
        assertThat(body(call(post("/politicas").session(root), policyRequest("Financeiro", false, "alertar"), 409))
            .get("mensagem").asText()).isEqualTo("Já existe uma política com esse nome.");
        call(post("/grupos").session(root), Map.of("nome", "Financeiro"), 409);
        call(put("/endpoints/" + agent.id() + "/grupo").session(root), Map.of("grupoId", group), 204);
        var groupDocument = body(agentCall("GET", "policy", agent, null, 200));
        assertThat(groupDocument.get("alertCategories").toString()).isEqualTo("[\"Cpf\",\"Rg\"]");
        // Editar cria versão nova; a padrão não pode ser apagada; política em uso por grupo também não.
        int edited = body(call(put("/politicas/" + other).session(root), policyRequest("Financeiro", false, "bloquear"), 200)).get("versao").asInt();
        assertThat(body(agentCall("GET", "policy", agent, null, 200)).get("version").asInt()).isEqualTo(edited);
        call(delete("/politicas/" + policyId).session(root), null, 409);
        call(delete("/politicas/" + other).session(root), null, 409);
        var detail = body(call(get("/politicas/" + other).session(root), null, 200));
        assertThat(detail.get("historico").size()).isEqualTo(2);
        var list = body(call(get("/politicas").session(root), null, 200));
        assertThat(list.size()).isEqualTo(2);

        // Eventos: gravados com o host autenticado; reenvio idêntico não duplica.
        var queuedEvent = event("qualquer-rotulo", "Blocked");
        var batch = Map.of("schemaVersion", 1, "hostname", "PC-FIN-01", "agentVersion", "0.2.0",
            "events", List.of(queuedEvent), "overrides", List.of());
        var receipt = body(agentCall("POST", "events", agent, batch, 200));
        assertThat(receipt.get("acceptedEvents").asInt()).isEqualTo(1);
        agentCall("POST", "events", agent, batch, 200);
        // A retry can cross an upgrade after the original receipt was lost. Exercise both persisted formats.
        try (var conn = DriverManager.getConnection(SERVER + "/app" + OPTIONS, USER, PASSWORD);
             var read = conn.prepareStatement("SELECT payload FROM agent_audit_ingest WHERE record_key = ?");
             var update = conn.prepareStatement("UPDATE agent_audit_ingest SET payload = ? WHERE record_key = ?")) {
            String key = "audit:" + queuedEvent.get("eventId");
            read.setString(1, key);
            ObjectNode stored;
            try (var rows = read.executeQuery()) {
                assertThat(rows.next()).isTrue();
                stored = (ObjectNode) json.readTree(rows.getString(1));
            }
            update.setString(2, key);
            stored.remove("customRules");
            update.setString(1, stored.toString());
            assertThat(update.executeUpdate()).isEqualTo(1);
            assertThat(body(agentCall("POST", "events", agent, batch, 200)).get("acceptedEvents").asInt()).isEqualTo(1);

            stored.putNull("customRules");
            update.setString(1, stored.toString());
            assertThat(update.executeUpdate()).isEqualTo(1);
            assertThat(body(agentCall("POST", "events", agent, batch, 200)).get("acceptedEvents").asInt()).isEqualTo(1);
        }
        var changedEvent = new java.util.HashMap<>(queuedEvent);
        changedEvent.put("customRules", List.of("Outra regra"));
        agentCall("POST", "events", agent, Map.of("events", List.of(changedEvent)), 409);
        var audit = body(call(get("/auditoria").session(root), null, 200));
        assertThat(audit.at("/resumo/total").asInt()).isEqualTo(1);
        assertThat(audit.at("/eventos/0/hostId").asInt()).isEqualTo(agent.id());
        String csv = call(get("/auditoria/exportar").session(root), null, 200).getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(csv).contains("\"'=planilha.txt\"").contains("\"Bloqueado\"").contains("PC-FIN-01");

        // Regras personalizadas: exemplos conferidos antes de salvar; nada é publicado para agente que não entende.
        var when = Map.of("todos", List.of(Map.of("contem", List.of("projeto atlas")), Map.of("mascara", "CT-####/##", "minimo", 2)));
        var wrongRule = Map.of("nome", "Contratos do Projeto Atlas", "quando", when, "exemplos", Map.of(
            "sinalizar", List.of("Projeto Atlas: CT-2041/26 e CT-2042/26"),
            "naoSinalizar", List.of("Projeto Atlas: CT-1/26 e CT-3333/33 e CT-4444/44")));
        assertThat(body(call(post("/regras").session(root), wrongRule, 400)).get("mensagem").asText())
            .contains("não deve ser sinalizado");
        var rule = Map.of("nome", "Contratos do Projeto Atlas", "quando", when, "exemplos", Map.of(
            "sinalizar", List.of("Projeto Atlas: CT-2041/26 e CT-2042/26"), "naoSinalizar", List.of("Projeto Atlas: CT-2041/26")));
        int ruleId = body(call(post("/regras").session(root), rule, 201)).get("id").asInt();
        var tested = body(call(post("/regras/testar").session(root),
            Map.of("quando", when, "textos", List.of("PROJETO ATLAS ct-1111/11 CT-2222/22", "nada")), 200));
        assertThat(tested.get(0).get("matched").asBoolean()).isTrue();
        assertThat(tested.get(1).get("matched").asBoolean()).isFalse();

        var withRule = new java.util.HashMap<String, Object>(policyRequest("Financeiro", false, "bloquear"));
        var config = new java.util.HashMap<String, Object>((Map<String, Object>) withRule.get("configuracao"));
        config.put("regrasPersonalizadas", Map.of(String.valueOf(ruleId), "alertar"));
        withRule.put("configuracao", config);
        assertThat(body(call(put("/politicas/" + other).session(root), withRule, 409)).get("mensagem").asText())
            .contains("não entendem regras personalizadas").contains("PC-FIN-01");
        agentCall("POST", "heartbeat", agent, Map.of("host", host("PC-FIN-01"), "formato_regras", 1), 200);
        int ruleVersion = body(call(put("/politicas/" + other).session(root), withRule, 200)).get("versao").asInt();
        var ruleDocument = body(agentCall("GET", "policy", agent, null, 200));
        assertThat(ruleDocument.get("version").asInt()).isEqualTo(ruleVersion);
        assertThat(ruleDocument.get("customRulesFormat").asInt()).isEqualTo(1);
        assertThat(ruleDocument.at("/customRules/0/name").asText()).isEqualTo("Contratos do Projeto Atlas");
        assertThat(ruleDocument.at("/customRules/0/alert").asBoolean()).isTrue();
        assertThat(ruleDocument.at("/customRules/0/when/all/1/pattern").asText()).isEqualTo("CT\\-[0-9][0-9][0-9][0-9]\\/[0-9][0-9]");
        assertThat(ruleDocument.get("alertCategories").toString()).contains("CustomRuleAlert");
        // Editar a regra cria uma versão nova da política; regra em uso não pode ser excluída.
        call(put("/regras/" + ruleId).session(root), rule, 200);
        assertThat(body(agentCall("GET", "policy", agent, null, 200)).get("version").asInt()).isGreaterThan(ruleVersion);
        assertThat(body(agentCall("GET", "policy", agent, null, 200)).at("/customRules/0/revision").asInt()).isEqualTo(2);
        call(delete("/regras/" + ruleId).session(root), null, 409);
        assertThat(body(call(get("/regras").session(root), null, 200)).at("/0/politicas/0").asText()).isEqualTo("Financeiro");
        // Evento bloqueado por regra aparece com o nome da regra no painel.
        var ruleEvent = new java.util.HashMap<String, Object>(event("PC-FIN-01", "Blocked"));
        ruleEvent.put("categories", List.of("CustomRule"));
        ruleEvent.put("customRules", List.of("Contratos do Projeto Atlas"));
        agentCall("POST", "events", agent, Map.of("schemaVersion", 1, "hostname", "PC-FIN-01", "agentVersion", "0.3.0",
            "events", List.of(ruleEvent), "overrides", List.of()), 200);
        assertThat(body(call(get("/painel").session(root), null, 200)).get("categoriasBloqueadas").toString())
            .contains("Regra: Contratos do Projeto Atlas");

        var mixed = new java.util.HashMap<>(event("PC-FIN-01", "Blocked"));
        mixed.put("categories", java.util.Arrays.stream(com.safeupload.audit.AuditContracts.Category.values())
            .map(Enum::name).toList());
        mixed.put("customRules", List.of("Regra de bloqueio", "Regra de alerta"));
        var mixedReceipt = body(agentCall("POST", "events", agent, Map.of("events", List.of(mixed)), 200));
        assertThat(mixedReceipt.get("acceptedEvents").asInt()).isEqualTo(1);
        verifyPolicyBudgets(root);

        // Assinatura: corpo trocado, replay, relógio fora da janela e host revogado são recusados.
        byte[] content = json.writeValueAsBytes(Map.of("host", host("PC-FIN-01")));
        long now = Instant.now().getEpochSecond();
        String nonce = UUID.randomUUID().toString();
        mvc.perform(signed("POST", "heartbeat", agent, content, now, nonce)).andExpect(status().isOk());
        mvc.perform(signed("POST", "heartbeat", agent, content, now, nonce)).andExpect(status().isUnauthorized());
        mvc.perform(signed("POST", "heartbeat", agent, content, now - 3600)).andExpect(status().isUnauthorized());
        var tampered = signed("POST", "heartbeat", agent, content, now + 1)
            .content(json.writeValueAsBytes(Map.of("host", host("OUTRO-NOME"))));
        mvc.perform(tampered).andExpect(status().isUnauthorized());
        mvc.perform(post("/agent/heartbeat").contentType(MediaType.APPLICATION_JSON).content(content))
            .andExpect(status().isUnauthorized());
        call(post("/endpoints/" + agent.id() + "/revogar").session(root), null, 204);
        agentCall("GET", "identity", agent, null, 403);
        agentCall("GET", "policy", agent, null, 403);
        assertThat(body(call(get("/painel").session(root), null, 200)).at("/maquinas/politicaDesatualizada").asInt()).isZero();

        // Segunda empresa: ROOT cria; o admin dela não vê nem altera nada da empresa A.
        call(post("/auth/normalregister/empresa/set").session(root), company("Empresa B", "22222222000122"), 201);
        int companyB = body(call(get("/auth/normalregister/empresa/list").session(root), null, 200)).findValues("id_empresa")
            .stream().mapToInt(JsonNode::asInt).max().orElseThrow();
        call(post("/auth/normalregister/usuario/set").session(root), Map.of("username", "adminb", "email", "admin@b.test",
            "cpf", "22222222222", "senha", "Senha-forte-2", "nome_completo", "Admin B", "data_nascimento", "1990-01-01",
            "fk_id_empresa", companyB, "endereco", address(), "role", "admin", "criado_por", "ignorado"), 201);
        var adminB = login("admin@b.test", "Senha-forte-2");
        assertThat(body(call(get("/endpoints").session(adminB), null, 200)).get("itens").size()).isZero();
        assertThat(body(call(get("/politicas").session(adminB), null, 200)).size()).isZero();
        assertThat(body(call(get("/auditoria").session(adminB), null, 200)).at("/resumo/total").asInt()).isZero();
        call(get("/politicas/" + policyId).session(adminB), null, 404);
        call(put("/endpoints/" + agent.id() + "/grupo").session(adminB), Map.of("grupoId", group), 404);
        call(post("/endpoints/" + agent.id() + "/revogar").session(adminB), null, 404);
        // ADMIN não cria ROOT nem usuário em outra empresa, e não cadastra empresa.
        call(post("/auth/normalregister/usuario/set").session(adminB), Map.of("username", "x", "email", "x@b.test",
            "cpf", "33333333333", "senha", "Senha-forte-3", "nome_completo", "X", "data_nascimento", "1990-01-01",
            "fk_id_empresa", companyB, "endereco", address(), "role", "root", "criado_por", "x"), 403);
        call(post("/auth/normalregister/empresa/set").session(adminB), company("Empresa C", "33333333000133"), 403);
        // Máquina cadastrada com token da empresa B pertence à B.
        var agentB = enroll(adminB, "PC-B-01");
        assertThat(body(call(get("/endpoints").session(adminB), null, 200)).at("/itens/0/hostId").asInt()).isEqualTo(agentB.id());
        agentCall("GET", "policy", agentB, null, 404);
    }
}
