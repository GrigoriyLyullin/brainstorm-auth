package com.brainstorm;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
public class BrainstormAuth {

    public static void main(String[] args) {
        SpringApplication.run(BrainstormAuth.class);
    }

}
