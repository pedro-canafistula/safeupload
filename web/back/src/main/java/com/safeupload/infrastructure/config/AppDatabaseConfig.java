package com.safeupload.infrastructure.config;

import javax.sql.DataSource;
import com.safeupload.domain.entity.app.*;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.lang.NonNull;

import jakarta.persistence.EntityManagerFactory;

@Configuration 
@EnableJpaRepositories (
    basePackages = "com.safeupload.infrastructure.repository.app",
    entityManagerFactoryRef = "appEntityManagerFactory",
    transactionManagerRef = "appTransactionManager"
)
public class AppDatabaseConfig {
    @Bean 
    @Primary 
    @ConfigurationProperties ("app.datasource")
    public DataSourceProperties appDataSourceProperties(){
        return new DataSourceProperties();
    }

    @Bean 
    @Primary 
    public DataSource appDataSource(){
        return appDataSourceProperties()
                .initializeDataSourceBuilder()
                .build();
    }

    @Bean 
    @Primary 
    public LocalContainerEntityManagerFactoryBean appEntityManagerFactory(
        EntityManagerFactoryBuilder builder,
        @Qualifier ("appDataSource") DataSource dataSource){
            return builder 
                    .dataSource(dataSource)
                    .packages(Host.class)
                    .persistenceUnit("app")
                    .build();
                    
    }

    @Bean 
    @Primary 
    public PlatformTransactionManager appTransactionManager (@Qualifier ("appEntityManagerFactory") @NonNull EntityManagerFactory entityManagerFactory){
            return new JpaTransactionManager(entityManagerFactory);
    }

}
