package com.safeupload.infrastructure.repository;

import com.safeupload.domain.entity.PoliticaEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PoliticaRepository extends JpaRepository<PoliticaEntity, Long> {
    Optional<PoliticaEntity> findFirstByAtivaTrue();
}
