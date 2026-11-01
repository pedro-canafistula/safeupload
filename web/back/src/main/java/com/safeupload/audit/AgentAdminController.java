package com.safeupload.audit;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Read-only routes consumed by the current Angular client. SecurityConfig requires admin/root. */
@RestController
public class AgentAdminController {
    private final AgentAdminQueries queries;
    public AgentAdminController(AgentAdminQueries queries) { this.queries = queries; }

    @GetMapping("/painel")
    public Map<String, Object> dashboard() { return queries.dashboard(); }

    @GetMapping("/auditoria")
    public Map<String, Object> audit(@RequestParam(defaultValue = "") String endpoint) {
        return queries.audit(endpoint);
    }

    @GetMapping("/endpoints")
    public Map<String, Object> endpoints(@RequestParam(defaultValue = "all") String status,
            @RequestParam(defaultValue = "all") String os, @RequestParam(defaultValue = "") String q) {
        return queries.endpoints(status, os, q);
    }
}
