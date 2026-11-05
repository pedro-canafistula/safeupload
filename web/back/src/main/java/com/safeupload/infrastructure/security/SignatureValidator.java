package com.safeupload.infrastructure.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import java.util.Base64;
import java.security.KeyFactory;
import java.security.Signature;

import org.springframework.stereotype.Component;

@Component 
public class SignatureValidator {
    public boolean validar(
        String chavePublicaBase64,
        String dados,
        String assinaturaBase64
    ) {
        try {
            byte[] chaveBytes = Base64.getDecoder()
                .decode(chavePublicaBase64);

            byte[] assinaturaBytes = Base64.getDecoder()
                .decode(assinaturaBase64);

            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");

            PublicKey chavePublica = keyFactory.generatePublic(
                new X509EncodedKeySpec(chaveBytes)
            );

            Signature signature = Signature.getInstance("Ed25519");

            signature.initVerify(chavePublica);

            signature.update(dados.getBytes(StandardCharsets.UTF_8));

            return signature.verify(assinaturaBytes);

        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }
}
