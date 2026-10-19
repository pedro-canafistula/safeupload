package com.safeupload.presentation.exception;

public class DatabaseErrorException extends RuntimeException {
    public DatabaseErrorException(String mensagem){
        super(mensagem);
    }
}
