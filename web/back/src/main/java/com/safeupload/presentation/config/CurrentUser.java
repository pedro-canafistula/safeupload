package com.safeupload.presentation.config;

import java.util.Locale;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import com.safeupload.infrastructure.repository.acesso.UsuarioRepository;

/** Quem está logado e a empresa dele. Toda consulta administrativa fica dentro dessa empresa. */
@Component
public class CurrentUser {
    public record Info(int idUsuario, String username, String email, int idEmpresa, String role) {
        public boolean root() { return role.equals("root"); }
    }

    private final UsuarioRepository usuarios;

    public CurrentUser(UsuarioRepository usuarios) { this.usuarios = usuarios; }

    public Info of(Authentication authentication) {
        if (authentication == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        var usuario = usuarios.findByEmail(authentication.getName())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Sessão inválida. Entre novamente."));
        if (usuario.getFkIdEmpresa() == null)
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Usuário sem empresa.");
        String role = usuario.getRole() == null ? "user" : usuario.getRole().trim().toLowerCase(Locale.ROOT);
        return new Info(usuario.getIdUsuario(), usuario.getUsername(), usuario.getEmail(),
            usuario.getFkIdEmpresa().getIdEmpresa(), role);
    }
}
