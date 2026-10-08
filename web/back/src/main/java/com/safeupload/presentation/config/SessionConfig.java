package com.safeupload.presentation.config;

import com.safeupload.application.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class SessionConfig implements WebMvcConfigurer {
    private final AuthService auth;

    public SessionConfig(AuthService auth) { this.auth = auth; }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new HandlerInterceptor() {
            @Override
            public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
                if ("OPTIONS".equals(request.getMethod())) return true;
                var session = request.getSession(false);
                if (session == null || auth.usuarioAtivo((Long) session.getAttribute("idUsuario")) == null) {
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Entre novamente para consultar os dados.");
                }
                return true;
            }
        }).addPathPatterns("/api/painel", "/api/auditoria", "/api/endpoints");
    }
}
