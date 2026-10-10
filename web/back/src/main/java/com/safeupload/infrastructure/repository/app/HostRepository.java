package com.safeupload.infrastructure.repository.app;

import org.springframework.data.jpa.repository.JpaRepository;

import com.safeupload.domain.entity.app.Host;

public interface HostRepository extends JpaRepository <Host, Long>{}
