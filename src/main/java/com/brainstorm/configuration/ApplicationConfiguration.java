package com.brainstorm.configuration;

import com.github.cloudyrock.mongock.Mongock;
import com.github.cloudyrock.mongock.SpringMongockBuilder;
import com.mongodb.MongoClient;
import lombok.Data;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
public class ApplicationConfiguration {

    public static final String CHANGELOGS_PACKAGE = "com.brainstorm.changelogs";

    private String database;

    @Bean
    public Mongock mongock(MongoProperties props, MongoClient mongoClient) {
        return new SpringMongockBuilder(mongoClient, props.getDatabase(), CHANGELOGS_PACKAGE).setLockQuickConfig().build();
    }
}
