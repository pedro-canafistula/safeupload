package com.safeupload.rules;

/** Validadores de dígito verificador, iguais aos do agente (CpfValidator, CnpjValidator, LuhnValidator, Mod11Validator). */
public final class RuleValidators {
    private RuleValidators() {}

    public static boolean valid(String validator, String value) {
        var digits = new StringBuilder();
        for (char c : value.toCharArray()) if (c >= '0' && c <= '9') digits.append(c);
        String d = digits.toString();
        return switch (validator) {
            case "cpf" -> cpf(d);
            case "cnpj" -> cnpj(d);
            case "luhn" -> d.length() >= 12 && d.length() <= 19 && luhn(d);
            case "mod11" -> mod11(d);
            default -> false;
        };
    }

    private static boolean allSame(String d) { return d.chars().distinct().count() == 1; }

    static boolean cpf(String d) {
        if (d.length() != 11 || allSame(d)) return false;
        for (int position = 9; position <= 10; position++) {
            int sum = 0;
            for (int i = 0; i < position; i++) sum += (d.charAt(i) - '0') * (position + 1 - i);
            int rest = (sum * 10) % 11;
            if (rest == 10) rest = 0;
            if (rest != d.charAt(position) - '0') return false;
        }
        return true;
    }

    static boolean cnpj(String d) {
        if (d.length() != 14 || allSame(d)) return false;
        int[] first = {5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2};
        int[] second = {6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2};
        return check(d, first, 12) && check(d, second, 13);
    }

    private static boolean check(String d, int[] weights, int position) {
        int sum = 0;
        for (int i = 0; i < weights.length; i++) sum += (d.charAt(i) - '0') * weights[i];
        int rest = sum % 11;
        return (rest < 2 ? 0 : 11 - rest) == d.charAt(position) - '0';
    }

    static boolean luhn(String d) {
        int sum = 0;
        boolean twice = false;
        for (int i = d.length() - 1; i >= 0; i--) {
            int digit = d.charAt(i) - '0';
            if (twice) { digit *= 2; if (digit > 9) digit -= 9; }
            sum += digit;
            twice = !twice;
        }
        return sum % 10 == 0;
    }

    /** Último dígito = verificador; pesos 2..9 da direita para a esquerda; resto menor que 2 dá 0, senão 11 − resto. */
    static boolean mod11(String d) {
        if (d.length() < 2) return false;
        int sum = 0, weight = 2;
        for (int i = d.length() - 2; i >= 0; i--) {
            sum += (d.charAt(i) - '0') * weight;
            weight = weight == 9 ? 2 : weight + 1;
        }
        int rest = sum % 11;
        return d.charAt(d.length() - 1) - '0' == (rest < 2 ? 0 : 11 - rest);
    }
}
