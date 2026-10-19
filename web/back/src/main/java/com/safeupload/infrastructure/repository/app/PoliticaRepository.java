package com.safeupload.infrastructure.repository.app;

import org.springframework.data.jpa.repository.JpaRepository;

import com.safeupload.domain.entity.app.Politica;

public interface PoliticaRepository extends JpaRepository <Politica, Integer>{}
