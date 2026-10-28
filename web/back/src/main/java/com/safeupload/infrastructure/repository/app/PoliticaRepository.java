package com.safeupload.infrastructure.repository.app;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.safeupload.domain.entity.app.Politica;

public interface PoliticaRepository extends JpaRepository <Politica, Integer>{
    List<Politica> findByFkIdHost_IdHost(Integer idHost);
}
