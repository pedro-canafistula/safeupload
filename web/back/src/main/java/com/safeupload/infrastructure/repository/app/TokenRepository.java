package com.safeupload.infrastructure.repository.app;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.safeupload.domain.entity.app.Token;

public interface TokenRepository extends JpaRepository<Token,Integer>{
    Optional<Token> findByToken(String token);
    boolean existsByToken(String token);
}