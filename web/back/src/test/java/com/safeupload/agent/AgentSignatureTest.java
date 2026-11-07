package com.safeupload.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

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

    @Test void a_valid_signature_cannot_bypass_the_clock_window_with_an_overflowing_timestamp() throws Exception {
        long now = 1_700_000_000L;
        long outsideWindow = Long.MIN_VALUE + now;
        var pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var hosts = mock(HostStore.class);
        when(hosts.credentials(7)).thenReturn(new HostStore.Credentials(
            Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()), false));
        var signer = Signature.getInstance("Ed25519");
        signer.initSign(pair.getPrivate());
        signer.update(AgentSignature.message("GET", "identity", 7, outsideWindow, NONCE, new byte[0])
            .getBytes(StandardCharsets.UTF_8));
        var request = new MockHttpServletRequest("GET", "/agent/identity");
        request.addHeader(AgentSignature.HOST, "7");
        request.addHeader(AgentSignature.TIME, Long.toString(outsideWindow));
        request.addHeader(AgentSignature.NONCE, NONCE);
        request.addHeader(AgentSignature.SIGNATURE, Base64.getEncoder().encodeToString(signer.sign()));
        var response = new MockHttpServletResponse();
        var chain = new MockFilterChain();
        new AgentAuthFilter(hosts, Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC))
            .doFilter(request, response, chain);
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(chain.getRequest()).isNull();
    }
}
