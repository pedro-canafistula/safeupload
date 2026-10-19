package com.safeupload.infrastructure.repository.app;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.safeupload.domain.entity.app.Host;

public interface HostRepository extends JpaRepository <Host, Integer>{
    Optional<Host> findByIp(String ip);
}
