package com.safeupload.infrastructure.repository;

import com.safeupload.domain.entity.ReceivedEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface ReceivedEventRepository extends JpaRepository<ReceivedEvent, String> {
    List<ReceivedEvent> findByKindOrderByOccurredAtUtcDescEventKeyAsc(String kind);
}
