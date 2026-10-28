package com.safeupload.presentation.exception;

import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
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
        logger.error("Falha de acesso ao banco durante uma requisição da API.", exception);
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

        return ResponseEntity
            .status(HttpStatus.CONFLICT)
            .body(Map.of(
                "status", HttpStatus.CONFLICT.value(),
                "erro", "ERRO_USUARIOS_EXISTENTES",
                "mensagem", e.getMessage()
            ));
    }


}
