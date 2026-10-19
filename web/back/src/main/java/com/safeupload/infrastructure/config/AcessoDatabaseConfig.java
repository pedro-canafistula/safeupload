package com.safeupload.infrastructure.config;

import javax.sql.DataSource;

import com.safeupload.domain.entity.acesso.*;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.lang.NonNull;

import jakarta.persistence.EntityManagerFactory;

@Configuration
@EnableJpaRepositories(
    basePackages = "com.safeupload.infrastructure.repository.acesso",
    entityManagerFactoryRef = "acessoEntityManagerFactory",
    transactionManagerRef = "acessoTransactionManager"
)
public class AcessoDatabaseConfig {

    @Bean
    @ConfigurationProperties("acesso.datasource")
    public DataSourceProperties acessoDataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean
    public DataSource acessoDataSource(
            @Qualifier("acessoDataSourceProperties")
            DataSourceProperties properties) {

        return properties
                .initializeDataSourceBuilder()
                .build();
    }

    @Bean
    public LocalContainerEntityManagerFactoryBean acessoEntityManagerFactory(
            EntityManagerFactoryBuilder builder,
            @Qualifier("acessoDataSource") DataSource dataSource) {

        return builder
                .dataSource(dataSource)
                .packages(Endereco.class)
                .persistenceUnit("acesso")
                .build();
    }

    @Bean
    public PlatformTransactionManager acessoTransactionManager(@Qualifier("acessoEntityManagerFactory") @NonNull EntityManagerFactory entityManagerFactory) {

        return new JpaTransactionManager(entityManagerFactory);
    }
}