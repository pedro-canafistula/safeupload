package com.safeupload.application.exception;

/** Mensagem já pronta para ser exibida ao usuário (equivalente ao ErroDeValidacao do Python). */
public class ErroDeValidacaoException extends RuntimeException {
    public ErroDeValidacaoException(String mensagem) {
        super(mensagem);
    }
}
