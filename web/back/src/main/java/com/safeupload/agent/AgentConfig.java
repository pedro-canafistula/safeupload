package com.safeupload.agent;

import java.time.Clock;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AgentConfig {
    @Bean
    public FilterRegistrationBean<AgentAuthFilter> agentAuthFilter(HostStore hosts, Clock clock) {
        var registration = new FilterRegistrationBean<>(new AgentAuthFilter(hosts, clock));
        registration.addUrlPatterns("/agent/*");
        return registration;
    }
}
