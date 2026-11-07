package com.safeupload.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class RulePatternTest {
    @Test void acceptsTheCommonSubsetAndNormalizesShortcuts() {
        assertThat(RulePattern.regex("a[b-d\\d_]+(?:x|y){2,3}?z").pattern()).isEqualTo("a[b-d0-9\\_]+(?:x|y){2,3}?z");
        assertThat(RulePattern.regex("[^&\\]]").pattern()).isEqualTo("[^\\&\\]]");
        assertThat(RulePattern.regex("(a)(b)").groups()).isEqualTo(2);
        assertThat(RulePattern.mask("AA-##").pattern()).isEqualTo("\\p{L}\\p{L}\\-[0-9][0-9]");
    }

    @Test void refusesWhatTheAgentWouldNotRunTheSameWay() {
        for (String pattern : List.of("(?=a)b", "(?!a)", "(?<=a)b", "(?<n>a)", "(a)\\1", "(?i)a", "^a", "a$", "\\p{L}",
                "a*+", "a{2", "a{2000}", "a{3,1}", "[a", "[]", "(a", "a)", "*a", "\\", "[\\D]", "\\Qa\\E", "[z-a]")) {
            assertThatThrownBy(() -> RulePattern.regex(pattern)).as(pattern).isInstanceOf(RulePattern.PatternException.class);
        }
        assertThatThrownBy(() -> RulePattern.mask("abc")).isInstanceOf(RulePattern.PatternException.class);
        // A posição aponta o caractere culpado (contando de 1).
        assertThatThrownBy(() -> RulePattern.regex("^CT")).hasMessageStartingWith("Posição 1: âncoras");
        assertThatThrownBy(() -> RulePattern.regex("ab*+")).hasMessageStartingWith("Posição 4: quantificadores seguidos");
        assertThatThrownBy(() -> RulePattern.regex("a(?=b)")).hasMessageStartingWith("Posição 3: \"(?\"");
    }

    @Test void refusesPatternsThatMatchEmptyTextAndBadConditions() {
        assertThatThrownBy(() -> leaf(new RuleDefinition.Condition(null, null, null, null, null, "a*", null, null, null, null)))
            .isInstanceOf(ResponseStatusException.class).hasMessageContaining("texto vazio");
        assertThatThrownBy(() -> leaf(new RuleDefinition.Condition(null, null, null, List.of("atlas!"), null, null, null, null, null, null)))
            .hasMessageContaining("começar e terminar");
        assertThatThrownBy(() -> leaf(new RuleDefinition.Condition(null, null, null, null, null, "(\\d+)", null, null, "rg", 1)))
            .hasMessageContaining("validador");
        assertThatThrownBy(() -> leaf(new RuleDefinition.Condition(null, null, null, null, null, "\\d+", null, null, "cpf", 1)))
            .hasMessageContaining("grupo validado");
        assertThatThrownBy(() -> leaf(new RuleDefinition.Condition(List.of(), null, null, null, null, null, null, null, null, null)))
            .hasMessageContaining("de 1 a 20");
    }

    private static void leaf(RuleDefinition.Condition condition) {
        new RuleDefinition(condition, null).compile();
    }
}
