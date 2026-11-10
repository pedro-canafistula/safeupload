package com.safeupload.presentation.exception;

import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;

/*
A classe trata erros relacionados às operações dos controllers 
*/

@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(ApiExceptionHandler.class);

    /*
    Retorna erro quando o Json recebido é válido, mas não é aceito pelos critérios do DTO
    */ 
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleDTOValidation(MethodArgumentNotValidException exception){
        logger.warn("event=api.request.rejected status=400 category=validation_failed");
        String message = exception.getBindingResult()
            .getFieldErrors()
            .stream()
            .map(error -> error.getField() + ": " + error.getDefaultMessage())
            .findFirst()
            .orElse("Um ou mais campos são inválidos.");

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(Map.of(
                    "status", HttpStatus.BAD_REQUEST.value(), 
                    "erro", "ERRO_VALIDACAO",
                    "mensagem", message
        ));
    }

    /*
    Retorna erro quando o Java não consegue converter o Json, ou seja, o json é mal-formatado
    */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleMalformedJson(HttpMessageNotReadableException exception){
        logger.warn("event=api.request.rejected status=400 category=malformed_json");
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(Map.of(
                    "status", HttpStatus.BAD_REQUEST.value(), 
                    "erro", "JSON_MALFORMADO",
                    "mensagem", "O json recebido é incompatível com o formato esperado."
                ));
    }

    /* Retorna erro quando ocorre violação de integridade no banco de dados. */ 
    @ExceptionHandler(DataIntegrityViolationException.class) 
    public ResponseEntity<Map<String, Object>> handleIntegrityError( DataIntegrityViolationException exception) { 
        logger.warn("event=api.request.rejected status=409 category=data_integrity_conflict");
        return ResponseEntity 
                .status(HttpStatus.CONFLICT) 
                .body(Map.of( 
                    "status", HttpStatus.CONFLICT.value(), 
                    "erro", "ERRO_INTEGRIDADE", 
                    "mensagem", "Os dados enviados violam uma restrição do banco de dados." 
            )); 
    } 
    
    /* Retorna erro genérico de acesso ao banco de dados. */ 
    @ExceptionHandler(DataAccessException.class) 
    public ResponseEntity<Map<String, Object>> handleDatabaseError( DataAccessException exception) { 
        logger.error("event=api.database.failure exceptionType={}", exception.getClass().getSimpleName());
        return ResponseEntity 
                .status(HttpStatus.INTERNAL_SERVER_ERROR) 
                .body(Map.of( 
                    "status", HttpStatus.INTERNAL_SERVER_ERROR.value(), 
                    "erro", "ERRO_ACESSO_BANCO", 
                    "mensagem", "Ocorreu um erro ao acessar o banco de dados." 
            )); 
    }

    @ExceptionHandler(DatabaseErrorException.class)
    public ResponseEntity<Map<String, Object>> handleDatabaseError(
        DatabaseErrorException e) {

        logger.warn("event=api.request.rejected status=409 category=business_conflict");

        return ResponseEntity
            .status(HttpStatus.CONFLICT)
            .body(Map.of(
                "status", HttpStatus.CONFLICT.value(),
                "erro", "ERRO_USUARIOS_EXISTENTES",
                "mensagem", e.getMessage()
            ));
    }

    @ExceptionHandler(AuthErrorException.class)
    public ResponseEntity<Map<String, Object>> handleAuthError(AuthErrorException e) {
        logger.warn("event=api.request.rejected status=401 category=authentication_failed");
        return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body(Map.of(
                "status", HttpStatus.UNAUTHORIZED.value(),
                "erro", "ERRO_AUTENTICACAO",
                "mensagem", e.getMessage()
            ));
    }



    /* Erros com status explícito (404, 409, 403...) levam a mensagem para a tela. */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handleStatus(ResponseStatusException e) {
        int status = e.getStatusCode().value();
        logger.warn("event=api.request.rejected status={} category={} exceptionType={}",
            status, statusCategory(status), e.getClass().getSimpleName());
        return ResponseEntity
            .status(status)
            .body(Map.of(
                "status", status,
                "erro", "ERRO_REQUISICAO",
                "mensagem", e.getReason() == null ? "Requisição recusada." : e.getReason()
            ));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpectedError(Exception exception) {
        logger.error("event=api.unexpected.failure exceptionType={}", exception.getClass().getSimpleName());
        return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(Map.of(
                "status", HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "erro", "ERRO_INTERNO",
                "mensagem", "Ocorreu um erro interno. Informe o identificador da requisição ao suporte."
            ));
    }

    private static String statusCategory(int status) {
        return switch (status) {
            case 400 -> "bad_request";
            case 401 -> "authentication_required";
            case 403 -> "forbidden";
            case 404 -> "not_found";
            case 409 -> "conflict";
            default -> "request_rejected";
        };
    }
}
