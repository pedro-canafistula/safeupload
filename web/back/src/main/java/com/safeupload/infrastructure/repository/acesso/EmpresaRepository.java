package com.safeupload.infrastructure.repository.acesso;

import com.safeupload.domain.entity.acesso.Empresa;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmpresaRepository extends JpaRepository<Empresa, Integer> {
    boolean existsByRazaoSocial(String razaoSocial);
}


