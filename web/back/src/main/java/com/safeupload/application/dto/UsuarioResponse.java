package com.safeupload.application.dto;

import com.safeupload.domain.entity.Usuario;

/** Nunca inclui a senha (nem o hash) — é o que a API pode devolver com segurança. */
public class UsuarioResponse {

    private Long idUsuario;
    private String nomeCompleto;
    private String username;
    private String email;
    private String role;

    public static UsuarioResponse de(Usuario usuario) {
        UsuarioResponse dto = new UsuarioResponse();
        dto.idUsuario = usuario.getIdUsuario();
        dto.nomeCompleto = usuario.getNomeCompleto();
        dto.username = usuario.getUsername();
        dto.email = usuario.getEmail();
        dto.role = usuario.getRole();
        return dto;
    }

    public Long getIdUsuario() { return idUsuario; }
    public String getNomeCompleto() { return nomeCompleto; }
    public String getUsername() { return username; }
    public String getEmail() { return email; }
    public String getRole() { return role; }
}
