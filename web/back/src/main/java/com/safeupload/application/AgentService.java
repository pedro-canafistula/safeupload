package com.safeupload.application;

import com.safeupload.application.dto.AgentContracts.*;
import com.safeupload.domain.entity.acesso.Empresa;
import com.safeupload.domain.entity.acesso.Usuario;
import com.safeupload.domain.entity.app.*;
import com.safeupload.infrastructure.repository.acesso.EmpresaRepository;
import com.safeupload.infrastructure.repository.acesso.UsuarioRepository;
import com.safeupload.infrastructure.repository.app.HostRepository;
import com.safeupload.infrastructure.repository.app.SolicitacaoRepository;
import com.safeupload.infrastructure.repository.app.UsuarioSoRepository;

import jakarta.persistence.EntityNotFoundException;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;

@Service
public class AgentService {

    private final HostRepository hostRepository;
    private final UsuarioSoRepository usuarioSoRepository;
    private final EmpresaRepository empresaRepository;
    private final UsuarioRepository usuarioRepository;
    private final SolicitacaoRepository solicitacaoRepository;
    private final Clock clock;

    public AgentService(
        HostRepository hostRepository,
        UsuarioSoRepository usuarioSoRepository,
        EmpresaRepository empresaRepository,
        UsuarioRepository usuarioRepository,
        SolicitacaoRepository solicitacaoRepository,
        Clock clock
    ) {
        this.hostRepository = hostRepository;
        this.usuarioSoRepository = usuarioSoRepository;
        this.empresaRepository = empresaRepository;
        this.usuarioRepository = usuarioRepository;
        this.solicitacaoRepository = solicitacaoRepository;
        this.clock = clock;
        
    }

    @Transactional
    public SynchronizeResponse synchronize (SynchronizeRequest request){
        Host host = new Host(
            request.host().ip(),
            request.host().mascara(),
            request.host().hostname(),
            request.host().sistema_operacional(),
            request.host().versao_so(),
            request.host().fabricante(),
            request.host().modelo(),
            request.host().mac_address(),
            request.host().numero_serie()
        );

        host = hostRepository.save(host);

         UsuarioSo usuarioSo = new UsuarioSo(
            request.usuarioSo().sid(),
            request.usuarioSo().usuario_so(),
            request.usuarioSo().dominio(),
            request.usuarioSo().admin(),
            LocalDateTime.now(clock),
            1, 
            host
        );

        usuarioSo = usuarioSoRepository.save(usuarioSo);

        return new SynchronizeResponse(HttpStatus.CREATED, host.getIdHost(), usuarioSo.getIdUsuarioSo());
    }

    @Transactional
    public HeartbeatResponse heartbeat(HeartbeatRequest request){

        UsuarioSo usuarioSo = usuarioSoRepository.findById(request.id_usuario_so())
                                .orElseThrow(() -> 
                                    new EntityNotFoundException("Usuário do sistema operacional não encontrado na base de dados.")
                                );

        usuarioSo.executeHeartbeat(LocalDateTime.now(clock), 1);

        return new HeartbeatResponse(HttpStatus.OK, "Heartbeat contabilizado"); 
    }

    @Transactional
    public TicketsResponse tickets (TicketsRequest request){
        UsuarioSo usuarioSo = usuarioSoRepository.findById(request.fk_id_usuario_so())
                                .orElseThrow(() -> 
                                    new EntityNotFoundException("Usuário do sistema operacional não encontrado na base de dados.")
                                );


        Solicitacao solicitacao = new Solicitacao(
            usuarioSo, 
            request.fk_id_empresa_designada(), 
            request.fk_id_admin_designado(), 
            request.descricao(), 
            0);

        solicitacao = solicitacaoRepository.save(solicitacao);

        return new TicketsResponse(HttpStatus.OK, "Solicitação criada com sucesso.");
    }
    

}
