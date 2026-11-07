package com.safeupload.rules;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * Uma regra personalizada como o console a envia: condições ("quando") e exemplos obrigatórios. {@link #compile()}
 * valida tudo e devolve a regra pronta para avaliar (exemplos, botão Testar) e para publicar ao agente.
 */
public record RuleDefinition(Condition quando, Examples exemplos) {

    /** Exatamente um de: todos, algum, nao, contem, mascara, regex. */
    public record Condition(List<Condition> todos, List<Condition> algum, Condition nao, List<String> contem,
                            String mascara, String regex, Integer minimo, Boolean ignorarCaixa, String validador,
                            Integer grupoValidado) {}

    public record Examples(List<String> sinalizar, List<String> naoSinalizar) {}

    static final int MAX_LEAVES = 20;
    static final int MAX_DEPTH = 4;
    private static final List<String> VALIDATORS = List.of("cpf", "cnpj", "luhn", "mod11");

    public Compiled compile() {
        if (quando == null) throw invalid("A regra precisa de pelo menos uma condição.");
        var leaves = new ArrayList<Leaf>();
        Node root = build(quando, 0, leaves, "Condição");
        if (leaves.isEmpty()) throw invalid("A regra precisa de pelo menos uma condição de palavras, máscara ou regex.");
        return new Compiled(root, leaves);
    }

    /** Confere os exemplos: cada "sinalizar" precisa casar e cada "não sinalizar" não pode casar. */
    public void checkExamples(Compiled compiled) {
        if (exemplos == null || exemplos.sinalizar() == null || exemplos.sinalizar().isEmpty()
                || exemplos.naoSinalizar() == null || exemplos.naoSinalizar().isEmpty())
            throw invalid("Informe pelo menos um exemplo que deve ser sinalizado e um que não deve.");
        if (exemplos.sinalizar().size() > 10 || exemplos.naoSinalizar().size() > 10)
            throw invalid("No máximo 10 exemplos de cada tipo.");
        int i = 0;
        for (String example : exemplos.sinalizar()) {
            i++;
            checkExample(example);
            if (!compiled.evaluate(example).matched())
                throw invalid("O exemplo " + i + " que deve ser sinalizado não foi.");
        }
        i = 0;
        for (String example : exemplos.naoSinalizar()) {
            i++;
            checkExample(example);
            if (compiled.evaluate(example).matched())
                throw invalid("O exemplo " + i + " que não deve ser sinalizado foi.");
        }
    }

    private static void checkExample(String example) {
        if (example == null || example.isBlank() || example.length() > 5000)
            throw invalid("Cada exemplo precisa de texto (até 5000 caracteres).");
    }

    // ---- construção ----

    private Node build(Condition c, int depth, List<Leaf> leaves, String where) {
        if (depth > MAX_DEPTH) throw invalid(where + ": condições aninhadas demais (máximo " + MAX_DEPTH + ").");
        int kinds = (c.todos() == null ? 0 : 1) + (c.algum() == null ? 0 : 1) + (c.nao() == null ? 0 : 1)
            + (c.contem() == null ? 0 : 1) + (c.mascara() == null ? 0 : 1) + (c.regex() == null ? 0 : 1);
        if (kinds != 1) throw invalid(where + ": escolha um tipo de condição.");
        if (c.todos() != null || c.algum() != null) {
            List<Condition> children = c.todos() != null ? c.todos() : c.algum();
            if (children.isEmpty() || children.size() > 20) throw invalid(where + ": de 1 a 20 condições no grupo.");
            var nodes = new ArrayList<Node>();
            for (int i = 0; i < children.size(); i++) {
                if (children.get(i) == null) throw invalid(where + ": condição vazia.");
                nodes.add(build(children.get(i), depth + 1, leaves, where + " " + (i + 1)));
            }
            return new Group(c.todos() != null, nodes);
        }
        if (c.nao() != null) return new Not(build(c.nao(), depth + 1, leaves, where));
        if (leaves.size() >= MAX_LEAVES) throw invalid("No máximo " + MAX_LEAVES + " condições por regra.");
        int minimum = c.minimo() == null ? 1 : c.minimo();
        if (minimum < 1 || minimum > 1000) throw invalid(where + ": o mínimo de ocorrências vai de 1 a 1000.");
        Leaf leaf;
        if (c.contem() != null) {
            if (c.validador() != null) throw invalid(where + ": validador só vale para máscara ou regex.");
            leaf = words(c.contem(), minimum, where);
        } else {
            leaf = pattern(c, minimum, where);
        }
        leaves.add(leaf);
        return leaf;
    }

    private static Leaf words(List<String> terms, int minimum, String where) {
        if (terms.isEmpty() || terms.size() > 50) throw invalid(where + ": de 1 a 50 palavras ou frases.");
        var folded = new ArrayList<String>();
        for (String term : terms) {
            String value = TextFold.fold(term == null ? "" : term).strip();
            if (value.isEmpty() || value.length() > 100)
                throw invalid(where + ": cada palavra ou frase precisa de 1 a 100 caracteres.");
            if (!Character.isLetterOrDigit(value.charAt(0)) || !Character.isLetterOrDigit(value.charAt(value.length() - 1)))
                throw invalid(where + ": \"" + term + "\" precisa começar e terminar com letra ou número.");
            if (!folded.contains(value)) folded.add(value);
        }
        var regex = new StringBuilder("\\b(?:");
        for (int i = 0; i < folded.size(); i++) {
            if (i > 0) regex.append('|');
            for (char ch : folded.get(i).toCharArray()) {
                if (Character.isLetterOrDigit(ch) || ch == ' ' || ch > 127) regex.append(ch);
                else regex.append('\\').append(ch);
            }
        }
        regex.append(")\\b");
        return new Leaf(true, folded, null, false, minimum, null, 0,
            Pattern.compile(regex.toString(), Pattern.UNICODE_CHARACTER_CLASS), describeWords(folded, minimum));
    }

    private static Leaf pattern(Condition c, int minimum, String where) {
        RulePattern.Normalized normalized;
        boolean mask = c.mascara() != null;
        try {
            normalized = mask ? RulePattern.mask(c.mascara()) : RulePattern.regex(c.regex());
        } catch (RulePattern.PatternException e) {
            throw invalid(where + ": " + e.getMessage());
        }
        String validator = c.validador() == null || c.validador().isBlank() ? null : c.validador();
        if (validator != null && !VALIDATORS.contains(validator))
            throw invalid(where + ": validador deve ser cpf, cnpj, luhn ou mod11.");
        int group = c.grupoValidado() == null ? 0 : c.grupoValidado();
        if (group < 0 || group > normalized.groups()) throw invalid(where + ": o grupo validado não existe na expressão.");
        if (group > 0 && validator == null) throw invalid(where + ": grupo validado só faz sentido com um validador.");
        boolean ignoreCase = c.ignorarCaixa() == null ? mask : c.ignorarCaixa();
        int flags = Pattern.UNICODE_CHARACTER_CLASS | (ignoreCase ? Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE : 0);
        Pattern compiled = Pattern.compile(normalized.pattern(), flags);
        for (String probe : new String[] {"", "a", "0", " ", "-"}) {
            Matcher m = compiled.matcher(probe);
            while (m.find()) if (m.end() == m.start()) throw invalid(where + ": a expressão não pode casar com texto vazio.");
        }
        String label = mask ? "máscara " + c.mascara() : "regex " + c.regex();
        return new Leaf(false, null, normalized.pattern(), ignoreCase, minimum, validator, group, compiled,
            (minimum > 1 ? "pelo menos " + minimum + "× " : "") + label + (validator == null ? "" : " (" + validator + ")"));
    }

    private static String describeWords(List<String> terms, int minimum) {
        return (minimum > 1 ? "pelo menos " + minimum + "× " : "") + "contém " + String.join(" ou ", terms.stream().map(t -> "\"" + t + "\"").toList());
    }

    static ResponseStatusException invalid(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    // ---- regra compilada ----

    sealed interface Node permits Group, Not, Leaf {}
    record Group(boolean all, List<Node> children) implements Node {}
    record Not(Node child) implements Node {}
    record Leaf(boolean words, List<String> terms, String pattern, boolean ignoreCase, int minimum, String validator,
                int group, Pattern compiled, String label) implements Node {}

    public record LeafResult(String condicao, int ocorrencias, boolean atende) {}
    public record Evaluation(boolean matched, List<LeafResult> condicoes) {}

    public static final class Compiled {
        private final Node root;
        private final List<Leaf> leaves;

        Compiled(Node root, List<Leaf> leaves) {
            this.root = root;
            this.leaves = leaves;
        }

        public Evaluation evaluate(String text) {
            String folded = TextFold.fold(text);
            var counts = new LinkedHashMap<Leaf, Integer>();
            for (Leaf leaf : leaves) counts.put(leaf, count(leaf, leaf.words() ? folded : text));
            var details = leaves.stream()
                .map(l -> new LeafResult(l.label(), counts.get(l), counts.get(l) >= l.minimum())).toList();
            return new Evaluation(eval(root, counts), details);
        }

        private static int count(Leaf leaf, String text) {
            Matcher m = leaf.compiled().matcher(text);
            int found = 0;
            while (m.find()) {
                String value = leaf.group() == 0 ? m.group() : m.group(leaf.group());
                if (leaf.validator() == null || (value != null && RuleValidators.valid(leaf.validator(), value))) found++;
            }
            return found;
        }

        private static boolean eval(Node node, Map<Leaf, Integer> counts) {
            return switch (node) {
                case Group g -> g.all() ? g.children().stream().allMatch(c -> eval(c, counts))
                    : g.children().stream().anyMatch(c -> eval(c, counts));
                case Not n -> !eval(n.child(), counts);
                case Leaf l -> counts.get(l) >= l.minimum();
            };
        }

        /** A condição no formato que o agente recebe ("when" em docs/console-agente.md). */
        public Map<String, Object> agentWhen() { return toAgent(root); }

        private static Map<String, Object> toAgent(Node node) {
            var out = new LinkedHashMap<String, Object>();
            switch (node) {
                case Group g -> out.put(g.all() ? "all" : "any", g.children().stream().map(Compiled::toAgent).toList());
                case Not n -> out.put("not", toAgent(n.child()));
                case Leaf l when l.words() -> {
                    out.put("words", l.terms());
                    if (l.minimum() > 1) out.put("min", l.minimum());
                }
                case Leaf l -> {
                    out.put("pattern", l.pattern());
                    if (l.ignoreCase()) out.put("ignoreCase", true);
                    if (l.minimum() > 1) out.put("min", l.minimum());
                    if (l.validator() != null) out.put("validator", l.validator());
                    if (l.group() > 0) out.put("group", l.group());
                }
            }
            return out;
        }
    }
}
