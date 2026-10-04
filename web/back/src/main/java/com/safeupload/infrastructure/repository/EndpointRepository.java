package com.safeupload.infrastructure.repository;

import com.safeupload.domain.entity.Endpoint;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface EndpointRepository extends JpaRepository<Endpoint, String> {
    List<Endpoint> findAllByOrderByLastSeenUtcDesc();
}
