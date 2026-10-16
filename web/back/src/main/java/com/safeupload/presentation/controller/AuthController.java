package com.safeupload.presentation.controller;

import com.safeupload.application.AuthService;
import com.safeupload.application.dto.AuthContracts.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import com.safeupload.infrastructure.repository.acesso.EmpresaRepository;
import com.safeupload.infrastructure.repository.acesso.UsuarioRepository;
import com.safeupload.presentation.exception.DatabaseErrorException;

import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.context.SecurityContextRepository;


import java.util.List;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final EmpresaRepository empresaRepository;
    private final UsuarioRepository usuarioRepository;
    private final AuthService service;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    public AuthController(
        EmpresaRepository empresaRepository,
        UsuarioRepository usuarioRepository,
        AuthService service,
        AuthenticationManager authenticationManager,
        SecurityContextRepository securityContextRepository
    ){
        this.empresaRepository = empresaRepository;
        this.usuarioRepository = usuarioRepository;
        this.service = service;
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
    }

    @GetMapping("/decision")
    public ResponseEntity<DecisionResponse> decision() {
        boolean existemUsuarios = usuarioRepository.count() > 0;

        DecisionResponse response = new DecisionResponse(
            HttpStatus.OK,
            existemUsuarios
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/firstregister")
    public ResponseEntity<DefaultPostResponse> firstRegister(@Valid @RequestBody FirstRegisterRequest request){
        if (usuarioRepository.count() > 0){
            throw new DatabaseErrorException(
                "Este endpoint não pode ser utilizado quando há usuários cadastrados na base."
            );
        }
        
        DefaultPostResponse response = service.firstRegister(request);
        return ResponseEntity
                .status(HttpStatus.CREATED.value())
                .body(response);
    }

    @PostMapping("/normalregister/empresa/set")
    public ResponseEntity<DefaultPostResponse> normalRegisterEmpresa(@Valid @RequestBody EmpresaRegister request){
        if (empresaRepository.existsByRazaoSocial(request.razao_social())){
            throw new DatabaseErrorException("A empresa já está cadastrada.");
        };

        DefaultPostResponse response = service.normalRegisterEmpresa(request);

        return ResponseEntity 
                .status(HttpStatus.CREATED.value())
                .body(response);
    }

    @GetMapping("/normalregister/empresa/list")
    public ResponseEntity<List<ListEmpresaResponse>> listEmpresa(){
        List<ListEmpresaResponse> response = empresaRepository.findAll()
                .stream()
                .map(empresa -> new ListEmpresaResponse(
                    empresa.getIdEmpresa(),
                    empresa.getRazaoSocial()
                ))
                .toList();
        return ResponseEntity.ok(response);
    }

    @PostMapping ("/normalregister/usuario/set")
    public ResponseEntity<DefaultPostResponse> normalRegisterUsuario(@Valid @RequestBody UsuarioRegister request){
        if (usuarioRepository.existsByUsername(request.username())){
            throw new DatabaseErrorException("Usuário já existe.");
        };

        if (usuarioRepository.existsByEmail(request.email())){
            throw new DatabaseErrorException("O E-mail já está em uso.");
        };

        if (usuarioRepository.existsByCpf(request.cpf())){
            throw new DatabaseErrorException("O CPF já está em uso.");
        };

        DefaultPostResponse response = service.normalRegisterUsuario(request);

        return ResponseEntity
                .status(HttpStatus.CREATED.value())
                .body(response);
    }

    @PostMapping ("/login")
    public ResponseEntity<DefaultPostResponse> login(
        @Valid @RequestBody LoginRequest request,
        HttpServletRequest requestHttp,
        HttpServletResponse responseHttp){

        service.login(request);    
        
        // Authentication authentication = authenticationManager.authenticate(
        //     new UsernamePasswordAuthenticationToken(
        //         request.email(),
        //         request.senha()
        //     )
        // );

        // SecurityContext context = SecurityContextHolder.createEmptyContext();
        // context.setAuthentication(authentication);
        // SecurityContextHolder.setContext(context);

        // securityContextRepository.saveContext(context, requestHttp, responseHttp);

        DefaultPostResponse response = new DefaultPostResponse(HttpStatus.OK, "Login realizado com êxito.");
        return ResponseEntity
                .status(HttpStatus.OK.value())
                .body(response);
    }
}
