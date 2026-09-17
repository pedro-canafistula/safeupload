package com.safeupload.infrastructure.repository;

import com.safeupload.domain.entity.Sessao;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessaoRepository extends JpaRepository<Sessao, Long> {
}
