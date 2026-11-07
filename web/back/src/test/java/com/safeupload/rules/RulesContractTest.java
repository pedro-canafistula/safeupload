package com.safeupload.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Casos compartilhados com o agente (SafeUpload.Agent.Tests/CustomRulesTests.cs): o servidor normaliza cada regra
 * para exatamente o "when" do arquivo e avalia cada texto como esperado; o agente, com o mesmo "when", também.
 */
class RulesContractTest {
    static final ObjectMapper JSON = new ObjectMapper();

    static JsonNode cases() throws Exception {
        try (InputStream in = RulesContractTest.class.getResourceAsStream("/regras-personalizadas-casos.json")) {
            return JSON.readTree(in);
        }
    }

    @Test void serverNormalizesAndEvaluatesTheSharedCases() throws Exception {
        for (JsonNode item : cases()) {
            String name = item.get("nome").asText();
            var condition = JSON.treeToValue(item.get("quando"), RuleDefinition.Condition.class);
            var compiled = new RuleDefinition(condition, null).compile();
            JsonNode normalized = JSON.valueToTree(compiled.agentWhen());
            assertThat(normalized).as(name).isEqualTo(item.get("when"));
            for (JsonNode text : item.get("textos"))
                assertThat(compiled.evaluate(text.get("texto").asText()).matched())
                    .as(name + " / " + text.get("texto").asText()).isEqualTo(text.get("esperado").asBoolean());
        }
    }

    @Test void foldMatchesTheAgentDefinition() {
        assertThat(TextFold.fold("Divulgação  AUTORIZADA\n—\tÉ-ótimo")).isEqualTo("divulgacao autorizada e otimo");
        assertThat(TextFold.fold("a b")).isEqualTo("a b");
    }

    @Test void validatorsAgreeWithKnownNumbers() {
        assertThat(RuleValidators.valid("cpf", "529.982.247-25")).isTrue();
        assertThat(RuleValidators.valid("cpf", "111.111.111-11")).isFalse();
        assertThat(RuleValidators.valid("cnpj", "11.222.333/0001-81")).isTrue();
        assertThat(RuleValidators.valid("luhn", "4111 1111 1111 1111")).isTrue();
        assertThat(RuleValidators.valid("mod11", "1234567-9")).isTrue();
        assertThat(RuleValidators.valid("mod11", "1234567-0")).isFalse();
    }

    @Test void examplesAreCheckedBeforeSaving() {
        var when = new RuleDefinition.Condition(null, null, null, List.of("projeto atlas"), null, null, null, null, null, null);
        var good = new RuleDefinition(when, new RuleDefinition.Examples(List.of("Projeto Atlas"), List.of("Atlas")));
        good.checkExamples(good.compile());
        var wrong = new RuleDefinition(when, new RuleDefinition.Examples(List.of("Projeto Atlas"), List.of("o projeto atlas")));
        assertThatThrownBy(() -> wrong.checkExamples(wrong.compile())).isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("O exemplo 1 que não deve ser sinalizado foi");
        var missing = new RuleDefinition(when, new RuleDefinition.Examples(List.of("Projeto Atlas"), List.of()));
        assertThatThrownBy(() -> missing.checkExamples(missing.compile())).isInstanceOf(ResponseStatusException.class);
    }
}
