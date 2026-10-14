package com.safeupload.application;

import com.safeupload.application.dto.AgentContracts.*;
import com.safeupload.domain.entity.app.*;
import com.safeupload.infrastructure.repository.app.HostRepository;
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
    private final Clock clock;

    public AgentService(
        HostRepository hostRepository,
        UsuarioSoRepository usuarioSoRepository,
        Clock clock) {
        this.hostRepository = hostRepository;
        this.clock = clock;
        this.usuarioSoRepository = usuarioSoRepository;
    }

    @Transactional
    public FirstSignalResponse firstSignal (FirstSignalRequest request){
        Host host = new Host(
            request.host().hostname(),
            request.host().ip(),
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

        return new FirstSignalResponse(HttpStatus.CREATED, host.getIdHost(), usuarioSo.getIdUsuarioSo());
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

    

}
