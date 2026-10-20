package com.safeupload.audit;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

/** Compatibility route consumed by the Windows agent; independent of enrollment. */
@RestController
public class AgentEventsController {
    private final AgentEventsStore store;

    public AgentEventsController(AgentEventsStore store) { this.store = store; }

    @PostMapping("/agent/events")
    public AuditContracts.Receipt events(@Valid @RequestBody AuditContracts.Batch batch) {
        return store.accept(batch);
    }
}
