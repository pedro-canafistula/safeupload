package com.safeupload.presentation.controller;

import com.safeupload.application.PolicyService;
import com.safeupload.application.dto.PolicyPublication.*;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/politicas")
public class PolicyController {
    private final PolicyService service;
    public PolicyController(PolicyService service) { this.service = service; }
    @GetMapping public List<Published> list() { return service.publications(); }
    @PostMapping public Published publish(@Valid @RequestBody Request request) { return service.publish(request); }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, String>> invalidPolicy(ResponseStatusException error) {
        return ResponseEntity.status(error.getStatusCode()).body(Map.of("message", error.getReason()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> invalidDocument(MethodArgumentNotValidException error) {
        return ResponseEntity.badRequest().body(Map.of("message", "Política inválida. Use esquema 1.0, nome, destino.endpointId, ação e pelo menos uma regra suportada."));
    }
}
