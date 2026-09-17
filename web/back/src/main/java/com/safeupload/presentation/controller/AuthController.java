package com.safeupload.presentation.controller;

import com.safeupload.application.AuthService;
import com.safeupload.application.dto.CadastroRequest;
import com.safeupload.application.dto.LoginRequest;
import com.safeupload.application.dto.UsuarioResponse;
import com.safeupload.application.exception.ErroDeValidacaoException;
import com.safeupload.domain.entity.Usuario;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletRequest request) {
        try {
            AuthService.ResultadoLogin resultado = authService.autenticar(
                    req.getEmail(),
                    req.getSenha(),
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")
            );

            Usuario usuario = resultado.usuario();
            HttpSession session = request.getSession(true);
            session.setAttribute("idUsuario", usuario.getIdUsuario());
            session.setAttribute("idSessao", resultado.idSessao());
            session.setAttribute("role", usuario.getRole());

            return ResponseEntity.ok(UsuarioResponse.de(usuario));
        } catch (ErroDeValidacaoException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("erro", e.getMessage()));
        }
    }

    @PostMapping("/cadastro")
    public ResponseEntity<?> cadastro(@RequestBody CadastroRequest req) {
        try {
            Usuario usuario = authService.cadastrar(req);
            return ResponseEntity.status(HttpStatus.CREATED).body(UsuarioResponse.de(usuario));
        } catch (ErroDeValidacaoException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("erro", e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            Long idSessao = (Long) session.getAttribute("idSessao");
            authService.encerrarSessao(idSessao);
            session.invalidate();
        }
        return ResponseEntity.ok(Map.of("mensagem", "Sessão encerrada."));
    }

    /** O Angular chama isso ao carregar a página para saber se já existe login ativo. */
    @GetMapping("/me")
    public ResponseEntity<?> me(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("idUsuario") == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(Map.of(
                "idUsuario", session.getAttribute("idUsuario"),
                "role", session.getAttribute("role")
        ));
    }
}
