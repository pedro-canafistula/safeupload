package com.safeupload.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/** Vetor fixo compartilhado com o agente C# (SignedRequestTests): se um lado mudar a mensagem, os dois quebram. */
class AgentSignatureTest {
    // Semente 0x00..0x1f; chave pública em SubjectPublicKeyInfo.
    static final String PUBLIC_KEY = "MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
    static final String SIGNATURE =
        "od2YTB6n1/a6PcmQjfqNYi4tR8Zz4wd8JYSxKvT87p2mneOCUIiC52aFVPjn46i5jqpiUXIHgQUp5JnwWCr3CQ==";
    static final String NONCE = "AAECAwQFBgcICQoLDA0ODw=="; // bytes 0x00..0x0f
    static final byte[] BODY = "{\"x\":1}".getBytes(StandardCharsets.UTF_8);

    @Test void messageMatchesTheDocumentedFormat() {
        assertThat(AgentSignature.message("POST", "heartbeat", 7, 1700000000L, NONCE, BODY)).isEqualTo(
            "SafeUpload-v1\nPOST\nheartbeat\n7\n1700000000\nAAECAwQFBgcICQoLDA0ODw==\n5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22");
        assertThat(AgentSignature.sha256(new byte[0]))
            .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    @Test void verifiesTheSharedVector() {
        assertThat(AgentSignature.verify(PUBLIC_KEY, AgentSignature.message("POST", "heartbeat", 7, 1700000000L, NONCE, BODY), SIGNATURE))
            .isTrue();
    }

    @Test void anyChangedFieldBreaksTheSignature() {
        byte[] otherBody = "{\"x\":2}".getBytes(StandardCharsets.UTF_8);
        assertThat(AgentSignature.verify(PUBLIC_KEY, AgentSignature.message("POST", "heartbeat", 7, 1700000000L, NONCE, otherBody), SIGNATURE)).isFalse();
        assertThat(AgentSignature.verify(PUBLIC_KEY, AgentSignature.message("POST", "events", 7, 1700000000L, NONCE, BODY), SIGNATURE)).isFalse();
        assertThat(AgentSignature.verify(PUBLIC_KEY, AgentSignature.message("POST", "heartbeat", 8, 1700000000L, NONCE, BODY), SIGNATURE)).isFalse();
        assertThat(AgentSignature.verify(PUBLIC_KEY, AgentSignature.message("POST", "heartbeat", 7, 1700000001L, NONCE, BODY), SIGNATURE)).isFalse();
        assertThat(AgentSignature.verify(PUBLIC_KEY, AgentSignature.message("POST", "heartbeat", 7, 1700000000L, "AAECAwQFBgcICQoLDA0OEA==", BODY), SIGNATURE)).isFalse();
        assertThat(AgentSignature.verify(PUBLIC_KEY, "x", "not base64!")).isFalse();
    }
}
