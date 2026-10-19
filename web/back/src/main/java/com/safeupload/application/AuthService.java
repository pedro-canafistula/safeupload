package com.safeupload.application;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;

import com.safeupload.application.dto.AuthContracts.DefaultPostResponse;
import com.safeupload.application.dto.AuthContracts.EmpresaRegister;
import com.safeupload.application.dto.AuthContracts.EnderecoRegister;
import com.safeupload.application.dto.AuthContracts.FirstRegisterRequest;
import com.safeupload.application.dto.AuthContracts.LoginRequest;
import com.safeupload.application.dto.AuthContracts.UsuarioRegister;
import com.safeupload.domain.entity.acesso.Empresa;
import com.safeupload.domain.entity.acesso.Endereco;
import com.safeupload.domain.entity.acesso.Usuario;
import com.safeupload.infrastructure.repository.acesso.EmpresaRepository;
import com.safeupload.infrastructure.repository.acesso.EnderecoRepository;
import com.safeupload.infrastructure.repository.acesso.UsuarioRepository;
import com.safeupload.presentation.exception.AuthErrorException;
import com.safeupload.presentation.exception.DatabaseErrorException;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.crypto.password.PasswordEncoder;

import jakarta.transaction.Transactional;

import java.time.Clock;

@Service 
public class AuthService {

    private final EnderecoRepository enderecoRepository;
    private final EmpresaRepository empresaRepository;
    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;

    public AuthService(
        EnderecoRepository enderecoRepository,
        EmpresaRepository empresaRepository,
        UsuarioRepository usuarioRepository,
        PasswordEncoder passwordEncoder,
        Clock clock
    ){
        this.enderecoRepository = enderecoRepository;
        this.empresaRepository = empresaRepository;
        this.usuarioRepository = usuarioRepository;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
    }

    @Transactional 
    public DefaultPostResponse firstRegister(FirstRegisterRequest request){
        Empresa empresa = empresaRegister(request.empresa());

        Endereco enderecoUsuario = enderecoRegister(request.endereco());

        Usuario usuario = new Usuario(
            request.username(),
            request.email(),
            request.cpf(),
            passwordEncoder.encode(request.senha()),
            request.nome_completo(),
            request.data_nascimento(),
            empresa,
            enderecoUsuario,
            0,
            "root",
            request.username(),
            LocalDateTime.now(clock)

        );

        usuario = usuarioRepository.save(usuario);

        return new DefaultPostResponse(
            HttpStatus.CREATED, 
            "Usuário cadastrado com sucesso."
        );
    }

    private Empresa empresaRegister (EmpresaRegister request){
        Endereco enderecoEmpresa = enderecoRegister(request.endereco());

        Empresa empresa = new Empresa(
            request.razao_social(),
            request.nome_fantasia(),
            request.cnpj(),
            request.email_contato(),
            request.telefone_contato(),
            enderecoEmpresa
        );

        empresa = empresaRepository.save(empresa);

        return empresa;
    }

    private Endereco enderecoRegister (EnderecoRegister request){
        Endereco endereco = new Endereco(
            request.cep(),
            request.logradouro(),
            request.numero(),
            request.complemento(),
            request.bairro(),
            request.cidade(),
            request.estado()
        );

        endereco = enderecoRepository.save(endereco);

        return endereco;
    }

    @Transactional 
    public DefaultPostResponse normalRegisterEmpresa (EmpresaRegister request){
        empresaRegister(request);
        return new DefaultPostResponse(
            HttpStatus.CREATED, 
            "Empresa cadastrada com sucesso.");
    }

    @Transactional 
    public DefaultPostResponse normalRegisterUsuario (UsuarioRegister request){
        Empresa empresa = empresaRepository.findById(request.fk_id_empresa())
            .orElseThrow(() -> new DatabaseErrorException("Empresa não encontrada."));

        Endereco enderecoUsuario = enderecoRegister(request.endereco());

        Usuario usuario = new Usuario (
            request.username(),
            request.email(),
            request.cpf(),
            passwordEncoder.encode(request.senha()),
            request.nome_completo(),
            request.data_nascimento(),
            empresa,
            enderecoUsuario,
            0,
            request.role(),
            request.criado_por(),
            LocalDateTime.now(clock)
        );

        usuario = usuarioRepository.save(usuario);

        return new DefaultPostResponse(
            HttpStatus.CREATED, 
            "Usuário cadastrado com sucesso."); 
    }

    public void login(LoginRequest request){
        Usuario usuario = usuarioRepository
            .findByEmail(request.email())
            .orElseThrow(() -> new AuthErrorException(
                "Usuário ou senha inválidos."
            ));

        if (!passwordEncoder.matches(
                request.senha(),
                usuario.getSenha())) {
            throw new AuthErrorException(
                "Usuário ou senha inválidos."
            );
        }

        if (usuario.getBloqueado() == 1) {
            throw new AuthErrorException("Usuário bloqueado.");
        }

    }
}

