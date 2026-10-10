package com.safeupload.application;

import com.safeupload.application.dto.AgentContracts.*;
import com.safeupload.domain.entity.app.*;
import com.safeupload.infrastructure.repository.app.HostRepository;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AgentService {

    private final HostRepository hostRepository;

    public AgentService(HostRepository hostRepository) {
        this.hostRepository = hostRepository;
    }

    @Transactional
    public FirstSignalResponse firstSignal(FirstSignalRequest request){
        Host host = new Host(
            request.hostname(),
            request.ip(),
            request.sistema_operacional(),
            request.versao_so(),
            request.fabricante(),
            request.modelo(),
            request.mac_address(),
            request.numero_serie()
        );

       
        Host savedHost = hostRepository.save(host);

        return new FirstSignalResponse(
            HttpStatus.CREATED.value(),
            savedHost.getIdHost(),
            "Host cadastrado com sucesso no banco de dados."
        );
        
    }

}
