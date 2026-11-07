package com.safeupload.agent;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Clock;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Autentica toda requisição /agent/** (menos /agent/enroll) pela assinatura Ed25519 do host.
 * O id do host autenticado fica no atributo {@link #HOST_ID}; os controllers nunca leem o id do corpo.
 */
public class AgentAuthFilter extends OncePerRequestFilter {
    public static final String HOST_ID = "safeupload.agent.hostId";
    static final int MAX_BODY = 4 * 1024 * 1024;
    static final long MAX_SKEW_SECONDS = 300;
    static final long REPLAY_WINDOW_SECONDS = 600;
    private static final java.util.regex.Pattern NONCE_FORMAT = java.util.regex.Pattern.compile("^[A-Za-z0-9+/=_-]{16,64}$");

    private final HostStore hosts;
    private final Clock clock;
    private final Map<String, Long> seen = new ConcurrentHashMap<>();

    public AgentAuthFilter(HostStore hosts, Clock clock) {
        this.hosts = hosts;
        this.clock = clock;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String route = route(request);
        return route == null || route.equals("enroll");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        int hostId;
        long time;
        String signature = request.getHeader(AgentSignature.SIGNATURE);
        String nonce = request.getHeader(AgentSignature.NONCE);
        try {
            hostId = Integer.parseInt(request.getHeader(AgentSignature.HOST));
            time = Long.parseLong(request.getHeader(AgentSignature.TIME));
        } catch (NumberFormatException e) {
            reject(response, HttpStatus.UNAUTHORIZED, "Requisição sem assinatura.");
            return;
        }
        if (signature == null || hostId <= 0 || nonce == null || !NONCE_FORMAT.matcher(nonce).matches()) {
            reject(response, HttpStatus.UNAUTHORIZED, "Requisição sem assinatura.");
            return;
        }
        long now = clock.instant().getEpochSecond();
        if (Math.abs(now - time) > MAX_SKEW_SECONDS) {
            reject(response, HttpStatus.UNAUTHORIZED, "Relógio do agente fora da janela de 5 minutos.");
            return;
        }
        byte[] body = request.getInputStream().readNBytes(MAX_BODY + 1);
        if (body.length > MAX_BODY) {
            reject(response, HttpStatus.PAYLOAD_TOO_LARGE, "Corpo grande demais.");
            return;
        }
        var host = hosts.credentials(hostId);
        String route = route(request) + (request.getQueryString() == null ? "" : "?" + request.getQueryString());
        String message = AgentSignature.message(request.getMethod(), route, hostId, time, nonce, body);
        if (host == null || !AgentSignature.verify(host.publicKey(), message, signature)) {
            reject(response, HttpStatus.UNAUTHORIZED, "Assinatura inválida.");
            return;
        }
        if (host.revoked()) {
            reject(response, HttpStatus.FORBIDDEN, "Máquina revogada no console.");
            return;
        }
        if (!firstUse(hostId + ":" + nonce, now)) {
            reject(response, HttpStatus.UNAUTHORIZED, "Requisição repetida.");
            return;
        }
        request.setAttribute(HOST_ID, hostId);
        chain.doFilter(new CachedBody(request, body), response);
    }

    /** Rota depois de "/agent/", ou null se a requisição não é do agente. */
    static String route(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return path.startsWith("/agent/") ? path.substring("/agent/".length()) : null;
    }

    private boolean firstUse(String key, long now) {
        if (seen.size() > 50_000 || (now & 63) == 0) {
            for (Iterator<Long> it = seen.values().iterator(); it.hasNext(); ) {
                if (it.next() < now) it.remove();
            }
        }
        return seen.putIfAbsent(key, now + REPLAY_WINDOW_SECONDS) == null;
    }

    private static void reject(HttpServletResponse response, HttpStatus status, String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"status\":" + status.value() + ",\"mensagem\":\"" + message + "\"}");
    }

    private static final class CachedBody extends HttpServletRequestWrapper {
        private final byte[] body;

        CachedBody(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            var input = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override public int read() { return input.read(); }
                @Override public int read(byte[] b, int off, int len) { return input.read(b, off, len); }
                @Override public boolean isFinished() { return input.available() == 0; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(ReadListener listener) { throw new UnsupportedOperationException(); }
            };
        }

        @Override
        public java.io.BufferedReader getReader() {
            return new java.io.BufferedReader(new java.io.InputStreamReader(getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
        }
    }
}
