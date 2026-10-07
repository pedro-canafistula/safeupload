package com.safeupload;

import com.safeupload.application.AgentService;
import com.safeupload.application.dto.AgentContracts.*;
import com.safeupload.infrastructure.repository.ReceivedEventRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;

class PersistenceRestartTest {
    @TempDir Path directory;

    @Test
    void endpointsEventsAndOverridesSurviveApplicationRestart() {
        String datasource = "jdbc:h2:file:" + directory.resolve("safeupload").toAbsolutePath().toString().replace('\\', '/');
        UUID eventId = UUID.randomUUID();
        try (var context = start(datasource)) {
            var service = context.getBean(AgentService.class);
            service.heartbeat(new Heartbeat("PC-PERSIST", "Máquina de teste", "Windows 11", "1.0.0", 1));
            service.submit(new SubmitEvents(List.of(new AuditEvent(eventId, OffsetDateTime.now(), "PC-PERSIST",
                    "teste", "persistido.txt", ".txt", 10L, Verdict.Blocked, List.of(Category.Cpf),
                    List.of("***"), "editor", 1, "C:\\SafeUpload", null, 1, 2L, false)),
                    List.of(new OverrideEvent(eventId, "Revisão", OffsetDateTime.now(), "teste", "PC-PERSIST"))));
        }
        try (var context = start(datasource)) {
            var service = context.getBean(AgentService.class);
            assertThat(service.endpoints()).hasSize(1);
            assertThat(service.auditEvents()).hasSize(1);
            assertThat(service.auditEvents().getFirst().eventId()).isEqualTo(eventId);
            assertThat(context.getBean(ReceivedEventRepository.class).count()).isEqualTo(2);
        }
    }

    private ConfigurableApplicationContext start(String datasource) {
        return new SpringApplicationBuilder(SafeuploadApplication.class).web(WebApplicationType.NONE).run(
                "--spring.datasource.url=" + datasource, "--spring.jpa.hibernate.ddl-auto=update",
                "--spring.h2.console.enabled=false", "--logging.level.root=WARN");
    }
}
