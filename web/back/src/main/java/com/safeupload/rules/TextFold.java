package com.safeupload.rules;

import java.text.Normalizer;

/**
 * Normalização das palavras das regras: minúsculas, sem acento, espaços/quebras de linha/hífens viram um espaço só.
 * Idêntica à do agente (TextFolder em CustomRules.cs); os casos compartilhados em
 * src/test/resources/regras-personalizadas-casos.json conferem os dois lados.
 */
public final class TextFold {
    private TextFold() {}

    public static String fold(String text) {
        var out = new StringBuilder(text.length());
        boolean lastWasSeparator = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (isSeparator(c)) {
                if (!lastWasSeparator) out.append(' ');
                lastWasSeparator = true;
                continue;
            }
            lastWasSeparator = false;
            if (c < 128 || Character.isSurrogate(c)) {
                out.append(Character.toLowerCase(c));
                continue;
            }
            for (char part : Normalizer.normalize(String.valueOf(c), Normalizer.Form.NFD).toCharArray()) {
                if (Character.getType(part) != Character.NON_SPACING_MARK) out.append(Character.toLowerCase(part));
            }
        }
        return out.toString();
    }

    static boolean isSeparator(char c) {
        return Character.getType(c) == Character.SPACE_SEPARATOR || "\t\n\r\f\u000B\u0085\u2028\u2029-".indexOf(c) >= 0
            || (c >= '\u2010' && c <= '\u2015');
    }
}
