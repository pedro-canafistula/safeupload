package com.safeupload.infrastructure.repository.app;

import org.springframework.data.jpa.repository.JpaRepository;

import com.safeupload.domain.entity.app.Solicitacao;

public interface SolicitacaoRepository extends JpaRepository<Solicitacao,Integer>{}