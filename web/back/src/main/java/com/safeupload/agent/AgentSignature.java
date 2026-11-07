package com.safeupload.agent;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Assinatura das requisições do agente (docs/console-agente.md, "Assinatura").
 * A mensagem cobre método, rota, host, horário e o hash do corpo: nada pode ser trocado no caminho.
 */
public final class AgentSignature {
    public static final String HOST = "X-SafeUpload-Host";
    public static final String TIME = "X-SafeUpload-Time";
    public static final String NONCE = "X-SafeUpload-Nonce";
    public static final String SIGNATURE = "X-SafeUpload-Signature";

    private AgentSignature() {}

    public static String message(String method, String route, int hostId, long time, String nonce, byte[] body) {
        return "SafeUpload-v1\n" + method + "\n" + route + "\n" + hostId + "\n" + time + "\n" + nonce + "\n" + sha256(body);
    }

    public static String enrollmentRecoveryMessage(String token) {
        return "SafeUpload-Enroll-Recovery-v1\n" + token;
    }

    public static boolean verify(String publicKeyBase64, String message, String signatureBase64) {
        try {
            PublicKey key = publicKey(publicKeyBase64);
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(message.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /** Chave pública Ed25519 em SubjectPublicKeyInfo (DER) codificada em Base64. */
    public static PublicKey publicKey(String base64) throws GeneralSecurityException {
        return KeyFactory.getInstance("Ed25519").generatePublic(
            new X509EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }

    public static String sha256(byte[] body) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
