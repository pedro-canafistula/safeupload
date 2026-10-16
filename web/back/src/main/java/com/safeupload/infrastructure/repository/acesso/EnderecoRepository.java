package com.safeupload.infrastructure.repository.acesso;

import com.safeupload.domain.entity.acesso.Endereco;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EnderecoRepository extends JpaRepository<Endereco, Integer> {
}


