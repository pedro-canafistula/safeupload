package com.safeupload.policy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * O formulário de política do console ("configuracao" em docs/console-agente.md) e a conversão para o documento
 * que o agente aplica sem tradução (o mesmo formato do policy.json local).
 */
public record PolicyConfig(
    Map<String, String> categorias,
    List<String> pastas,
    Boolean pendrives,
    Boolean rede,
    List<String> extensoes,
    Integer tamanhoMaximoMb,
    Integer tempoLimiteSegundos,
    Boolean permitirJustificativa,
    String clipboard,
    Map<String, String> regrasPersonalizadas
) {
    /** Uma regra personalizada já compilada, como o agente a recebe. */
    public record AgentRule(int id, int revision, String name, Map<String, Object> when) {}

    /** Código do console → categorias do agente. */
    public static final Map<String, List<String>> CATEGORIES = categories();
    private static final Pattern LOCAL_PATH = Pattern.compile("^[A-Za-z]:\\\\[^<>\"|?*\\p{Cntrl}]*$");
    private static final Pattern UNC_PATH = Pattern.compile("^\\\\\\\\[^\\\\/<>\"|?*\\p{Cntrl}]+\\\\[^\\\\/<>\"|?*\\p{Cntrl}]+(\\\\[^<>\"|?*\\p{Cntrl}]*)?$");
    private static final Pattern EXTENSION = Pattern.compile("^\\.[A-Za-z0-9]{1,10}$");
    private static final List<String> EXCLUDED_PROCESSES = List.of("System", "SafeUpload.Agent.App");

    private static Map<String, List<String>> categories() {
        var map = new LinkedHashMap<String, List<String>>();
        map.put("cpf", List.of("Cpf"));
        map.put("cnpj", List.of("Cnpj"));
        map.put("rg", List.of("Rg"));
        map.put("cartao_credito", List.of("PaymentCard"));
        map.put("dados_bancarios", List.of("BankData"));
        map.put("credenciais", List.of("Password", "Secret"));
        map.put("dados_saude", List.of("HealthData"));
        map.put("dados_pessoais", List.of("PersonalData"));
        map.put("documentos_confidenciais", List.of("ConfidentialDocument"));
        return Map.copyOf(map);
    }

    /** Valida e devolve a configuração normalizada (extensões em minúsculas, sem duplicatas). */
    public PolicyConfig validated() {
        if (categorias == null || !categorias.keySet().equals(CATEGORIES.keySet()))
            throw invalid("Informe a ação das 9 categorias.");
        boolean any = false;
        for (String action : categorias.values()) {
            if (!List.of("bloquear", "alertar", "ignorar").contains(action))
                throw invalid("Ação de categoria inválida: use bloquear, alertar ou ignorar.");
            any |= !action.equals("ignorar");
        }
        var rules = new java.util.TreeMap<String, String>();
        for (var entry : (regrasPersonalizadas == null ? Map.<String, String>of() : regrasPersonalizadas).entrySet()) {
            if (entry.getKey() == null || !entry.getKey().matches("[1-9][0-9]{0,8}"))
                throw invalid("Regra personalizada inválida na política.");
            if (!List.of("bloquear", "alertar", "ignorar").contains(entry.getValue()))
                throw invalid("Ação de regra inválida: use bloquear, alertar ou ignorar.");
            if (!entry.getValue().equals("ignorar")) {
                rules.put(entry.getKey(), entry.getValue());
                any = true;
            }
        }
        if (rules.size() > 50) throw invalid("No máximo 50 regras personalizadas por política.");
        if (!any) throw invalid("Pelo menos uma categoria ou regra precisa bloquear ou alertar.");

        var folders = new ArrayList<String>();
        var seenFolders = new HashSet<String>();
        for (String folder : pastas == null ? List.<String>of() : pastas) {
            String path = folder == null ? "" : folder.trim();
            if (path.length() > 260 || !(LOCAL_PATH.matcher(path).matches() || UNC_PATH.matcher(path).matches()))
                throw invalid("Pasta inválida: use C:\\caminho ou \\\\servidor\\compartilhamento.");
            while (path.length() > 3 && path.endsWith("\\")) path = path.substring(0, path.length() - 1);
            if (seenFolders.add(path.toLowerCase(Locale.ROOT))) folders.add(path);
        }
        if (folders.size() > 32) throw invalid("No máximo 32 pastas protegidas.");

        var exts = new ArrayList<String>();
        for (String extension : extensoes == null ? List.<String>of() : extensoes) {
            String value = extension == null ? "" : extension.trim().toLowerCase(Locale.ROOT);
            if (!value.startsWith(".")) value = "." + value;
            if (!EXTENSION.matcher(value).matches()) throw invalid("Extensão inválida: " + extension);
            if (!exts.contains(value)) exts.add(value);
        }
        if (exts.isEmpty() || exts.size() > 64) throw invalid("Informe de 1 a 64 extensões.");
        if (tamanhoMaximoMb == null || tamanhoMaximoMb < 1 || tamanhoMaximoMb > 4096)
            throw invalid("Tamanho máximo deve ficar entre 1 e 4096 MB.");
        if (tempoLimiteSegundos == null || tempoLimiteSegundos < 5 || tempoLimiteSegundos > 3600)
            throw invalid("Tempo limite deve ficar entre 5 e 3600 segundos.");
        if (!List.of("desligado", "alertar", "bloquear").contains(clipboard))
            throw invalid("Clipboard deve ser desligado, alertar ou bloquear.");
        return new PolicyConfig(Map.copyOf(categorias), List.copyOf(folders), Boolean.TRUE.equals(pendrives),
            Boolean.TRUE.equals(rede), List.copyOf(exts), tamanhoMaximoMb, tempoLimiteSegundos,
            Boolean.TRUE.equals(permitirJustificativa), clipboard, Map.copyOf(rules));
    }

    /** Ids das regras que a política usa (ação diferente de "ignorar"). */
    public List<Integer> ruleIds() {
        return (regrasPersonalizadas == null ? Map.<String, String>of() : regrasPersonalizadas).entrySet().stream()
            .filter(e -> !"ignorar".equals(e.getValue())).map(e -> Integer.valueOf(e.getKey())).sorted().toList();
    }

    public Map<String, Object> agentDocument(int version) { return agentDocument(version, Map.of()); }

    /** Documento que o agente recebe em GET /agent/policy; {@code rules} traz as regras usadas, por id. */
    public Map<String, Object> agentDocument(int version, Map<Integer, AgentRule> rules) {
        Set<String> active = new java.util.TreeSet<>();
        Set<String> alert = new java.util.TreeSet<>();
        CATEGORIES.forEach((code, agentCategories) -> {
            String action = categorias.get(code);
            if (action.equals("ignorar")) return;
            active.addAll(agentCategories);
            if (action.equals("alertar")) alert.addAll(agentCategories);
        });
        var scopes = new LinkedHashMap<String, Object>();
        scopes.put("extensions", extensoes);
        scopes.put("destinationPaths", pastas);
        scopes.put("removableDrives", pendrives);
        scopes.put("networkPaths", rede);
        var customRules = new java.util.ArrayList<Map<String, Object>>();
        for (int id : ruleIds()) {
            AgentRule rule = rules.get(id);
            if (rule == null) throw new IllegalStateException("Regra " + id + " da política não encontrada.");
            boolean alertRule = "alertar".equals(regrasPersonalizadas.get(String.valueOf(id)));
            active.add(alertRule ? "CustomRuleAlert" : "CustomRule");
            if (alertRule) alert.add("CustomRuleAlert");
            var item = new LinkedHashMap<String, Object>();
            item.put("id", rule.id());
            item.put("revision", rule.revision());
            item.put("name", rule.name());
            item.put("alert", alertRule);
            item.put("when", rule.when());
            customRules.add(item);
        }
        var document = new LinkedHashMap<String, Object>();
        document.put("version", version);
        document.put("activeCategories", List.copyOf(active));
        document.put("alertCategories", List.copyOf(alert));
        document.put("monitoredScopes", scopes);
        document.put("maxFileSizeMb", tamanhoMaximoMb);
        document.put("inspectionTimeoutSeconds", tempoLimiteSegundos);
        document.put("overrideAllowed", permitirJustificativa);
        document.put("failOpen", false);
        document.put("excludedProcesses", EXCLUDED_PROCESSES);
        document.put("clipboard", Map.of("mode", switch (clipboard) {
            case "alertar" -> "Audit";
            case "bloquear" -> "Block";
            default -> "Off";
        }));
        if (!customRules.isEmpty()) {
            document.put("customRulesFormat", 1);
            document.put("customRules", customRules);
        }
        return document;
    }

    private static ResponseStatusException invalid(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
