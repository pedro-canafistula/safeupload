package com.safeupload.application;

import com.safeupload.application.dto.CadastroRequest;
import com.safeupload.application.exception.ErroDeValidacaoException;
import com.safeupload.domain.entity.Sessao;
import com.safeupload.domain.entity.Usuario;
import com.safeupload.infrastructure.repository.SessaoRepository;
import com.safeupload.infrastructure.repository.UsuarioRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.regex.Pattern;

@Service
public class AuthService {

    private static final Pattern RE_EMAIL =
            Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[a-zA-Z]{2,}$");
    private static final Pattern RE_USERNAME =
            Pattern.compile("^[a-z0-9._-]{3,50}$");

    private final UsuarioRepository usuarios;
    private final SessaoRepository sessoes;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public AuthService(UsuarioRepository usuarios, SessaoRepository sessoes) {
        this.usuarios = usuarios;
        this.sessoes = sessoes;
    }

    // ------------------------------------------------------------ cadastro
    public Usuario cadastrar(CadastroRequest dados) {
        String nome = dados.getNomeCompleto() == null ? "" : dados.getNomeCompleto().trim();
        String username = dados.getUsername() == null ? "" : dados.getUsername().trim().toLowerCase();
        String email = dados.getEmail() == null ? "" : dados.getEmail().trim().toLowerCase();
        String cpf = somenteDigitos(dados.getCpf());

        if (nome.isBlank() || nome.split("\\s+").length < 2) {
            throw new ErroDeValidacaoException("Informe o nome completo.");
        }
        if (!RE_USERNAME.matcher(username).matches()) {
            throw new ErroDeValidacaoException(
                    "Nome de usuário deve ter de 3 a 50 caracteres (letras, números, . _ -).");
        }
        if (!RE_EMAIL.matcher(email).matches()) {
            throw new ErroDeValidacaoException("E-mail inválido.");
        }
        if (!cpfValido(cpf)) {
            throw new ErroDeValidacaoException("CPF inválido.");
        }
        if (dados.getSenha() == null || dados.getSenha().length() < 8) {
            throw new ErroDeValidacaoException("A senha deve ter pelo menos 8 caracteres.");
        }
        if (!dados.getSenha().equals(dados.getConfirmarSenha())) {
            throw new ErroDeValidacaoException("As senhas não conferem.");
        }

        LocalDate nascimento = null;
        if (dados.getDataNascimento() != null && !dados.getDataNascimento().isBlank()) {
            try {
                nascimento = LocalDate.parse(dados.getDataNascimento());
            } catch (DateTimeParseException e) {
                throw new ErroDeValidacaoException("Data de nascimento inválida.");
            }
        }

        if (usuarios.existsByEmail(email)) {
            throw new ErroDeValidacaoException("Já existe uma conta com esse e-mail.");
        }
        if (usuarios.existsByUsername(username)) {
            throw new ErroDeValidacaoException("Já existe uma conta com esse nome de usuário.");
        }
        if (usuarios.existsByCpf(cpf)) {
            throw new ErroDeValidacaoException("Já existe uma conta com esse CPF.");
        }

        // O primeiro usuário do sistema vira admin; os demais entram como 'user'.
        String role = usuarios.count() == 0 ? "admin" : "user";

        Usuario usuario = new Usuario();
        usuario.setNomeCompleto(nome);
        usuario.setUsername(username);
        usuario.setEmail(email);
        usuario.setCpf(cpf);
        usuario.setSenha(encoder.encode(dados.getSenha()));
        usuario.setDataNascimento(nascimento);
        usuario.setRole(role);
        usuario.setBloqueado(false);
        usuario.setDataCadastro(LocalDateTime.now());

        return usuarios.save(usuario);
    }

    // ------------------------------------------------------------- login
    public record ResultadoLogin(Usuario usuario, Long idSessao) {}

    public ResultadoLogin autenticar(String email, String senha, String ip, String agente) {
        String emailNormalizado = email == null ? "" : email.trim().toLowerCase();
        Usuario usuario = usuarios.findByEmail(emailNormalizado).orElse(null);

        if (usuario == null) {
            registrarSessao(null, ip, agente, false, "usuario_inexistente");
            // Mensagem genérica de propósito: não revela se o e-mail existe.
            throw new ErroDeValidacaoException("E-mail ou senha incorretos.");
        }
        if (usuario.isBloqueado()) {
            registrarSessao(usuario.getIdUsuario(), ip, agente, false, "usuario_bloqueado");
            throw new ErroDeValidacaoException("Esta conta está bloqueada. Procure um administrador.");
        }
        if (!encoder.matches(senha == null ? "" : senha, usuario.getSenha())) {
            registrarSessao(usuario.getIdUsuario(), ip, agente, false, "senha_incorreta");
            throw new ErroDeValidacaoException("E-mail ou senha incorretos.");
        }

        Sessao sessao = registrarSessao(usuario.getIdUsuario(), ip, agente, true, "login_ok");
        return new ResultadoLogin(usuario, sessao.getIdSessao());
    }

    public void encerrarSessao(Long idSessao) {
        if (idSessao == null) return;
        sessoes.findById(idSessao).ifPresent(sessao -> {
            if (sessao.getDataHoraLogout() == null) {
                sessao.setDataHoraLogout(LocalDateTime.now());
                sessoes.save(sessao);
            }
        });
    }

    private Sessao registrarSessao(Long idUsuario, String ip, String agente, boolean sucesso, String motivo) {
        Sessao sessao = new Sessao();
        sessao.setFkIdUsuario(idUsuario);
        sessao.setIpOrigem(ip);
        sessao.setAgenteConexao(agente);
        sessao.setStatusFinal(sucesso);
        sessao.setMotivo(motivo);
        return sessoes.save(sessao);
    }

    // ------------------------------------------------------------- utils
    private static String somenteDigitos(String valor) {
        return valor == null ? "" : valor.replaceAll("\\D", "");
    }

    /** Validação dos dois dígitos verificadores do CPF. */
    private static boolean cpfValido(String cpf) {
        if (cpf.length() != 11 || cpf.chars().distinct().count() == 1) {
            return false;
        }
        for (int tamanho : new int[]{9, 10}) {
            int soma = 0;
            for (int i = 0; i < tamanho; i++) {
                soma += (cpf.charAt(i) - '0') * (tamanho + 1 - i);
            }
            int digito = (soma * 10 % 11) % 10;
            if (digito != (cpf.charAt(tamanho) - '0')) {
                return false;
            }
        }
        return true;
    }
}
