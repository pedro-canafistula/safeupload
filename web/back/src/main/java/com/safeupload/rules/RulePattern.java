package com.safeupload.rules;

/**
 * Lê uma regex do administrador com uma gramática própria e devolve a forma normalizada que o agente (.NET,
 * NonBacktracking) e o backend (Java) entendem igual. Só aceita o subconjunto comum: literais, classes [...], ".",
 * grupos ( ) e (?: ), alternância e quantificadores * + ? {n} {n,} {n,m} (gulosos ou preguiçosos), com os atalhos
 * \d \D \w \W \s \S \b. Recusa lookaround, referência a grupo, âncoras ^ $, flags embutidas e o resto.
 */
public final class RulePattern {
    public record Normalized(String pattern, int groups) {}

    public static final class PatternException extends IllegalArgumentException {
        PatternException(String message) { super(message); }
    }

    private static final String DIGIT = "0-9";
    private static final String WORD = "\\p{L}\\p{N}_";
    private static final String SPACE = " \\t\\n\\r\\f";

    private final String input;
    private final StringBuilder out = new StringBuilder();
    private int pos;
    private int groups;
    private int depth;

    private RulePattern(String input) { this.input = input; }

    public static Normalized regex(String pattern) {
        if (pattern == null || pattern.isEmpty()) throw new PatternException("Expressão vazia.");
        if (pattern.length() > 500) throw new PatternException("Expressão com mais de 500 caracteres.");
        var parser = new RulePattern(pattern);
        parser.alternation();
        if (parser.pos < pattern.length()) throw parser.error("parêntese ')' sem abertura");
        return new Normalized(parser.out.toString(), parser.groups);
    }

    /** Máscara: # = dígito, A = letra; o resto vale literalmente. */
    public static Normalized mask(String mask) {
        if (mask == null || mask.length() < 3 || mask.length() > 100)
            throw new PatternException("A máscara precisa ter de 3 a 100 caracteres.");
        if (mask.indexOf('#') < 0 && mask.indexOf('A') < 0)
            throw new PatternException("A máscara precisa de pelo menos um # (dígito) ou A (letra); para texto fixo, use \"Contém palavras\".");
        var out = new StringBuilder();
        for (char c : mask.toCharArray()) {
            if (c == '#') out.append("[0-9]");
            else if (c == 'A') out.append("\\p{L}");
            else literal(out, c);
        }
        return new Normalized(out.toString(), 0);
    }

    private static void literal(StringBuilder out, char c) {
        if (Character.isLetterOrDigit(c) || c == ' ' || c > 127) out.append(c);
        else if (c == '\t') out.append("\\t");
        else if (c == '\n') out.append("\\n");
        else if (c == '\r') out.append("\\r");
        else if (c < 32) throw new PatternException("Caractere de controle na expressão.");
        else out.append('\\').append(c);
    }

    private PatternException error(String what) { return errorAt(pos, what); }

    /** {@code at} é o índice (0-based) do caractere culpado; a mensagem conta a partir de 1. */
    private PatternException errorAt(int at, String what) {
        return new PatternException("Posição " + (at + 1) + ": " + what + ".");
    }

    private boolean more() { return pos < input.length(); }
    private char peek() { return input.charAt(pos); }

    private void alternation() {
        sequence();
        while (more() && peek() == '|') {
            pos++;
            out.append('|');
            sequence();
        }
    }

    private void sequence() {
        while (more() && peek() != '|' && peek() != ')') {
            atom();
            quantifier();
        }
    }

    private void atom() {
        int at = pos;
        char c = input.charAt(pos++);
        switch (c) {
            case '(' -> {
                if (++depth > 10) throw errorAt(at, "grupos aninhados demais");
                if (input.startsWith("?:", pos)) { pos += 2; out.append("(?:"); }
                else if (more() && peek() == '?') throw error("\"(?\" só é aceito como \"(?:\" (sem lookahead, lookbehind, nomes ou flags)");
                else { out.append('('); groups++; }
                alternation();
                if (!more() || peek() != ')') throw error("falta fechar o parêntese");
                pos++;
                out.append(')');
                depth--;
            }
            case '[' -> charClass();
            case '.' -> out.append("[^\\n]");
            case '\\' -> escape();
            case '^', '$' -> throw errorAt(at, "âncoras ^ e $ não são aceitas (a regra procura no texto inteiro)");
            case '*', '+', '?' -> throw errorAt(at, "quantificador \"" + c + "\" sem nada antes");
            case '{' -> throw errorAt(at, "chave \"{\" fora de um quantificador; use \\{ para o caractere");
            case ']', '}' -> literal(out, c);
            default -> literal(out, c);
        }
    }

    private void escape() {
        if (!more()) throw error("barra invertida no fim");
        char c = input.charAt(pos++);
        switch (c) {
            case 'd' -> out.append("[" + DIGIT + "]");
            case 'D' -> out.append("[^" + DIGIT + "]");
            case 'w' -> out.append("[" + WORD + "]");
            case 'W' -> out.append("[^" + WORD + "]");
            case 's' -> out.append("[" + SPACE + "]");
            case 'S' -> out.append("[^" + SPACE + "]");
            case 'b' -> out.append("\\b");
            case 't' -> out.append("\\t");
            case 'n' -> out.append("\\n");
            case 'r' -> out.append("\\r");
            default -> {
                if (Character.isLetterOrDigit(c))
                    throw error("\\" + c + " não é aceito (referências a grupo e classes como \\p não fazem parte do subconjunto)");
                out.append('\\').append(c);
            }
        }
    }

    private void quantifier() {
        if (!more()) return;
        char c = peek();
        if (c == '*' || c == '+' || c == '?') {
            pos++;
            out.append(c);
        } else if (c == '{') {
            int close = input.indexOf('}', pos);
            if (close < 0) throw error("quantificador {n,m} sem fechar");
            String body = input.substring(pos + 1, close);
            if (!body.matches("\\d{1,4}(,\\d{0,4})?")) throw error("quantificador {" + body + "} inválido");
            String[] parts = body.split(",", -1);
            int min = Integer.parseInt(parts[0]);
            Integer max = parts.length == 1 ? Integer.valueOf(min) : parts[1].isEmpty() ? null : Integer.valueOf(parts[1]);
            if (min > 1000 || (max != null && (max > 1000 || max < min)))
                throw error("quantificador {" + body + "} fora de 0..1000");
            out.append('{').append(body).append('}');
            pos = close + 1;
        } else {
            return;
        }
        if (more() && peek() == '?') { pos++; out.append('?'); }
        if (more() && (peek() == '+' || peek() == '*' || peek() == '?' || peek() == '{'))
            throw error("quantificadores seguidos não são aceitos");
    }

    private void charClass() {
        out.append('[');
        if (more() && peek() == '^') { pos++; out.append('^'); }
        int members = 0;
        while (true) {
            if (!more()) throw error("classe [...] sem fechar");
            char c = input.charAt(pos);
            if (c == ']' && members > 0) { pos++; break; }
            if (c == ']') throw error("classe [] vazia");
            if (c == '[') throw error("classe dentro de classe não é aceita");
            String first = classChar();
            members++;
            if (first.length() == 1 && more() && peek() == '-' && pos + 1 < input.length() && input.charAt(pos + 1) != ']') {
                pos++;
                String last = classChar();
                if (last.length() != 1) throw error("intervalo com atalho (\\d, \\w...) não é aceito");
                if (last.charAt(0) < first.charAt(0)) throw error("intervalo invertido");
                classLiteral(first.charAt(0));
                out.append('-');
                classLiteral(last.charAt(0));
            } else if (first.length() == 1) {
                classLiteral(first.charAt(0));
            } else {
                out.append(first.substring(1)); // atalho já expandido, marcado com prefixo \0
            }
        }
        out.append(']');
    }

    /** Um caractere literal da classe, ou "\0" + expansão de um atalho (\d, \w, \s). */
    private String classChar() {
        char c = input.charAt(pos++);
        if (c != '\\') return String.valueOf(c);
        if (!more()) throw error("barra invertida no fim");
        char e = input.charAt(pos++);
        return switch (e) {
            case 'd' -> "\0" + DIGIT;
            case 'w' -> "\0" + WORD;
            case 's' -> "\0" + SPACE;
            case 't' -> "\t";
            case 'n' -> "\n";
            case 'r' -> "\r";
            case 'D', 'W', 'S' -> throw error("\\" + e + " dentro de [...] não é aceito; use [^...]");
            default -> {
                if (Character.isLetterOrDigit(e)) throw error("\\" + e + " não é aceito dentro de [...]");
                yield String.valueOf(e);
            }
        };
    }

    private void classLiteral(char c) {
        if (Character.isLetterOrDigit(c) || c > 127 || c == ' ') out.append(c);
        else if (c == '\t') out.append("\\t");
        else if (c == '\n') out.append("\\n");
        else if (c == '\r') out.append("\\r");
        else if (c < 32) throw new PatternException("Caractere de controle na expressão.");
        else out.append('\\').append(c); // inclui & (interseção no Java), [ ] ^ - \
    }
}
