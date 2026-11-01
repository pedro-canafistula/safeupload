package com.safeupload.infrastructure.repository.app;

import org.springframework.data.jpa.repository.JpaRepository;

import com.safeupload.domain.entity.app.Regras;

public interface RegrasRepository extends JpaRepository<Regras,Integer>{}
