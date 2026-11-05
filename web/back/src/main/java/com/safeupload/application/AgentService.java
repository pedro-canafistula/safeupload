package com.safeupload.application;

import com.safeupload.application.dto.AgentContracts.*;

import com.safeupload.domain.entity.app.*;
import com.safeupload.infrastructure.repository.acesso.EmpresaRepository;
import com.safeupload.infrastructure.repository.acesso.UsuarioRepository;
import com.safeupload.infrastructure.repository.app.HostRepository;
import com.safeupload.infrastructure.repository.app.PoliticaRepository;
import com.safeupload.infrastructure.repository.app.RegrasRepository;
import com.safeupload.infrastructure.repository.app.SolicitacaoRepository;
import com.safeupload.infrastructure.repository.app.TokenRepository;
import com.safeupload.infrastructure.security.SignatureValidator;

import jakarta.persistence.EntityNotFoundException;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;

@Service
public class AgentService {

    private final HostRepository hostRepository;
 
    private final SolicitacaoRepository solicitacaoRepository;
    private final TokenRepository tokenRepository;
    private final SignatureValidator signatureValidator;
    private final PoliticaRepository politicaRepository;
    private final Clock clock;

    public AgentService(
        HostRepository hostRepository,
        EmpresaRepository empresaRepository,
        UsuarioRepository usuarioRepository,
        SolicitacaoRepository solicitacaoRepository,
        TokenRepository tokenRepository,
        SignatureValidator signatureValidator,
        PoliticaRepository politicaRepository,
        RegrasRepository regrasRepository,
        Clock clock
    ) {
        this.hostRepository = hostRepository;
        this.solicitacaoRepository = solicitacaoRepository;
        this.tokenRepository = tokenRepository;
        this.signatureValidator = signatureValidator;
        this.politicaRepository = politicaRepository;
        this.clock = clock;
        
    }


    @Transactional
    public HeartBeatResponse heartbeat(HeartBeatRequest request){
        if (request.cadastro() != null){
            Token token = tokenRepository.findByToken(request.cadastro().token())
                            .orElseThrow(() -> new IllegalArgumentException("Token inválido."));

            if (token.getAtivo() != 1) {
                throw new IllegalArgumentException("Token inválido.");
            }

            Host host = new Host(
                request.host().ip(),
                request.host().mascara(),
                request.cadastro().chave_publica(),
                request.host().hostname(),
                request.host().sistema_operacional(),
                request.host().versao_so(),
                request.host().mac_address(),
                LocalDateTime.now(clock),
                1);

            Host hostSalvo = hostRepository.save(host);

            token.desativarToken();

            return new HeartBeatResponse(
                new DefaultResponse(HttpStatus.OK, "Host cadastrado"),
                hostSalvo.getIdHost(), 
                null);
        }

        SignatureValidation(request.autenticacao());

        Host host = hostRepository.findById(request.autenticacao().id_host())
        .orElseThrow(() -> new EntityNotFoundException(
            "Host não encontrado."
        ));

        host.atualizarDados(request.host(), LocalDateTime.now(clock));

        Politica politica = politicaRepository
            .findFirstByFkIdHost_IdHostOrderByIdPoliticaDesc(host.getIdHost())
            .orElse(null);

        String mensagem;

        if (politica == null) {
            mensagem = "Nenhuma política encontrada para este host.";

            return new HeartBeatResponse(
                new DefaultResponse(HttpStatus.OK, mensagem),
                host.getIdHost(),
                null
            );
        } else {
            mensagem = "Heartbeat contabilizado com sucesso.";
        }

        Regras regras = politica.getFkIdRegras();

        return new HeartBeatResponse(
            new DefaultResponse(HttpStatus.OK, mensagem),
            host.getIdHost(),
            new PoliticaResponse(
                politica.getIdPolitica(),
                politica.getVersao(),
                politica.getNome(),
                politica.getAcao(),
                politica.getOrigem(),
                new RegrasResponse(
                    regras.getBloquearCpf(),
                    regras.getBloquearCnpj(),
                    regras.getBloquearRg(),
                    regras.getBloquearDadosBancarios(),
                    regras.getBloquearCartaoCredito(),
                    regras.getBloquearCredenciais(),
                    regras.getBloquearDadosSaude(),
                    regras.getBloquearDadosPessoais(),
                    regras.getBloquearDocumentosConfidenciais()
                )
            )
        ); 
    }

    private void SignatureValidation(BasicAuthRequest auth){
        Host host = hostRepository.findById(auth.id_host())
                        .orElseThrow(() -> new EntityNotFoundException("Host não encontrado."));

        String chavePublica = host.getChavePublica();

        boolean assinaturaValida = signatureValidator.validar(
            chavePublica,
            String.valueOf(auth.id_host()),
            auth.assinatura()
        );

        if (!assinaturaValida) {
            throw new BadCredentialsException("Credenciais inválidas.");
        }

    }



    @Transactional
    public DefaultResponse tickets (TicketsRequest request){
        Host host = hostRepository.findById(request.fk_id_host())
                                .orElseThrow(() -> 
                                    new EntityNotFoundException("Usuário do sistema operacional não encontrado na base de dados.")
                                );


        Solicitacao solicitacao = new Solicitacao(
            host, 
            request.fk_id_empresa_designada(), 
            request.fk_id_admin_designado(), 
            request.descricao(), 
            0);

        solicitacao = solicitacaoRepository.save(solicitacao);

        return new DefaultResponse(HttpStatus.OK, "Solicitação criada com sucesso.");
    }
    

}
