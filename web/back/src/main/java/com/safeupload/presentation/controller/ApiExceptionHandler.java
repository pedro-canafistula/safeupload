package com.safeupload.presentation.controller;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.util.Map;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<?> invalidRequest(Exception exception) {
        return ResponseEntity.unprocessableEntity().body(Map.of("erro", "Dados inválidos. Verifique os campos e informe datas com fuso horário."));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<?> conflict(DataIntegrityViolationException exception) {
        return ResponseEntity.status(409).body(Map.of("erro", "Conflito de dados. Nenhum lote parcial foi confirmado; tente novamente."));
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<?> status(ResponseStatusException exception) {
        return ResponseEntity.status(exception.getStatusCode()).body(Map.of("erro", exception.getReason() == null ? "Solicitação recusada." : exception.getReason()));
    }
}
