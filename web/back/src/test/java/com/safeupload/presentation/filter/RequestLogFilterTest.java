package com.safeupload.presentation.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.HandlerMapping;

class RequestLogFilterTest {
    @Test
    void generatesResponseCorrelationIdAndClearsMdcAfterRequest() throws Exception {
        var filter = new RequestLogFilter();
        var request = new MockHttpServletRequest("GET", "/auth/me");
        request.addHeader(RequestLogFilter.REQUEST_ID_HEADER, "untrusted-client-value");
        request.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, "/auth/me");
        var response = new MockHttpServletResponse();

        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
            assertTrue(MDC.get(RequestLogFilter.REQUEST_ID) != null);
        });

        UUID requestId = UUID.fromString(response.getHeader(RequestLogFilter.REQUEST_ID_HEADER));
        assertTrue(requestId.toString().length() == 36);
        assertNotEquals("untrusted-client-value", response.getHeader(RequestLogFilter.REQUEST_ID_HEADER));
        assertEquals(200, response.getStatus());
        assertNull(MDC.get(RequestLogFilter.REQUEST_ID));
    }
}
