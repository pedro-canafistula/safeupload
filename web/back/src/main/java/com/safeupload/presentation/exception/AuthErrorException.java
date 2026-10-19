package com.safeupload.presentation.exception;

public class AuthErrorException extends RuntimeException{
    public AuthErrorException(String mensagem){
        super(mensagem);
    }
}
