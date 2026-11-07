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

    @Test
    void consoleAndAgentWorkTogetherInsideOneCompany() throws Exception {
        // Primeiro cadastro: empresa A + root.
        call(post("/auth/firstregister"), Map.of("username", "root", "email", "root@a.test", "cpf", "11111111111",
            "senha", "Senha-forte-1", "nome_completo", "Root A", "data_nascimento", "1990-01-01",
            "empresa", company("Empresa A", "11111111000111"), "endereco", address()), 201);
        var root = login("root@a.test", "Senha-forte-1");

        // Máquina cadastrada por token; sem política atribuída o agente recebe 404.
        var agent = enroll(root, "PC-FIN-01");
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
        var batch = Map.of("schemaVersion", 1, "hostname", "PC-FIN-01", "agentVersion", "0.2.0",
            "events", List.of(event("qualquer-rotulo", "Blocked")), "overrides", List.of());
        var receipt = body(agentCall("POST", "events", agent, batch, 200));
        assertThat(receipt.get("acceptedEvents").asInt()).isEqualTo(1);
        agentCall("POST", "events", agent, batch, 200);
        var audit = body(call(get("/auditoria").session(root), null, 200));
        assertThat(audit.at("/resumo/total").asInt()).isEqualTo(1);
        assertThat(audit.at("/eventos/0/hostId").asInt()).isEqualTo(agent.id());
        String csv = call(get("/auditoria/exportar").session(root), null, 200).getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(csv).contains("\"'=planilha.txt\"").contains("\"Bloqueado\"").contains("PC-FIN-01");

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
        agentCall("GET", "policy", agent, null, 403);

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
