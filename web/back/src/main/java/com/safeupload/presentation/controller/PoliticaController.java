package com.safeupload.presentation.controller;

import com.safeupload.application.PoliticaService;
import com.safeupload.application.dto.Politica;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/politicas")
public class PoliticaController {
    private final PoliticaService service;

    public PoliticaController(PoliticaService service) { this.service = service; }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Politica salvar(@Valid @RequestBody Politica politica) { return service.salvar(politica); }

    @GetMapping({"", "/ativa"})
    public Politica buscarAtiva() { return service.buscarAtiva(); }
}
