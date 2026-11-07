package com.safeupload.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class PolicyConfigTest {
    static Map<String, String> categories(String action) {
        var map = new HashMap<String, String>();
        PolicyConfig.CATEGORIES.keySet().forEach(code -> map.put(code, action));
        return map;
    }

    static PolicyConfig config(Map<String, String> categories) {
        return new PolicyConfig(categories, List.of("C:\\Dados\\Financeiro\\", "\\\\srv\\publico"), true, false,
            List.of("TXT", ".docx", ".txt"), 100, 900, true, "bloquear", null);
    }

    @Test void translatesActionsScopesAndLimitsToTheAgentDocument() {
        var categories = categories("ignorar");
        categories.put("cpf", "bloquear");
        categories.put("rg", "alertar");
        categories.put("credenciais", "alertar");
        var document = config(categories).validated().agentDocument(42);

        assertThat(document.get("version")).isEqualTo(42);
        assertThat(document.get("activeCategories")).isEqualTo(List.of("Cpf", "Password", "Rg", "Secret"));
        assertThat(document.get("alertCategories")).isEqualTo(List.of("Password", "Rg", "Secret"));
        assertThat(document.get("monitoredScopes")).isEqualTo(Map.of(
            "extensions", List.of(".txt", ".docx"),
            "destinationPaths", List.of("C:\\Dados\\Financeiro", "\\\\srv\\publico"),
            "removableDrives", true, "networkPaths", false));
        assertThat(document.get("maxFileSizeMb")).isEqualTo(100);
        assertThat(document.get("inspectionTimeoutSeconds")).isEqualTo(900);
        assertThat(document.get("overrideAllowed")).isEqualTo(true);
        assertThat(document.get("failOpen")).isEqualTo(false);
        assertThat(document.get("clipboard")).isEqualTo(Map.of("mode", "Block"));
    }

    @Test void rejectsIncompleteOrMeaninglessPolicies() {
        assertThatThrownBy(() -> config(categories("ignorar")).validated()).isInstanceOf(ResponseStatusException.class);
        var missing = categories("bloquear");
        missing.remove("rg");
        assertThatThrownBy(() -> config(missing).validated()).isInstanceOf(ResponseStatusException.class);
        var wrong = categories("bloquear");
        wrong.put("cpf", "talvez");
        assertThatThrownBy(() -> config(wrong).validated()).isInstanceOf(ResponseStatusException.class);
        for (String folder : List.of("relativo\\pasta", "C:", "\\\\srv", "C:\\a|b", "D:/barra")) {
            var bad = new PolicyConfig(categories("bloquear"), List.of(folder), true, true, List.of(".txt"), 1, 5, false, "desligado", null);
            assertThatThrownBy(bad::validated).as(folder).isInstanceOf(ResponseStatusException.class);
        }
        var noExtensions = new PolicyConfig(categories("bloquear"), List.of(), true, true, List.of(), 1, 5, false, "desligado", null);
        assertThatThrownBy(noExtensions::validated).isInstanceOf(ResponseStatusException.class);
        var tooBig = new PolicyConfig(categories("bloquear"), List.of(), true, true, List.of(".txt"), 5000, 5, false, "desligado", null);
        assertThatThrownBy(tooBig::validated).isInstanceOf(ResponseStatusException.class);
    }
}
