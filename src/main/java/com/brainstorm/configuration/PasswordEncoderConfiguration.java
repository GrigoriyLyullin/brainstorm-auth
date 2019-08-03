package com.brainstorm.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configuration for PasswordEncoder bean that uses BCryptPasswordEncoder. It should be in a separate configuration to
 * avoid cyclic dependencies between Spring Beans.
 */
@Configuration
public class PasswordEncoderConfiguration {

    @Value("${brainstorm.bcrypt.rounds}")
    private int bcryptRounds;

    /**
     * Encoder for the user password that uses BCryptPasswordEncoder.
     *
     * @return encoder bean
     */
    @Bean
    public PasswordEncoder userPasswordEncoder() {
        return new BCryptPasswordEncoder(bcryptRounds);
    }
}
