package com.brainstorm.configuration;

import com.brainstorm.domain.OauthClientDetails;
import com.brainstorm.repository.OauthClientDetailsRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableAuthorizationServer
@Import(ServerWebSecurityConfiguration.class)
public class OAuth2AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    private AuthenticationManager authenticationManager;

    private UserDetailsService userDetailsService;

    private OauthClientDetailsRepository oauthClientDetailsRepository;

    @Value("${brainstorm.jwtSigningKey}")
    private String jwtSigningKey;

    public OAuth2AuthorizationServerConfiguration(AuthenticationManager authenticationManager,
                                                  UserDetailsService userDetailsService,
                                                  OauthClientDetailsRepository oauthClientDetailsRepository) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.oauthClientDetailsRepository = oauthClientDetailsRepository;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.tokenStore(tokenStore()).accessTokenConverter(accessTokenConverter())
                .authenticationManager(authenticationManager).userDetailsService(userDetailsService);
    }


    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer.checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientId -> {
            try {
                OauthClientDetails clientDetails = oauthClientDetailsRepository.findByClientId(clientId);
                if (clientDetails != null) {
                    BaseClientDetails client = new BaseClientDetails(clientDetails.getClientId(),
                            clientDetails.getResourceIds(),
                            clientDetails.getScope(),
                            clientDetails.getAuthorizedGrantTypes(),
                            clientDetails.getAuthorities());

                    client.setAccessTokenValiditySeconds(clientDetails.getAccessTokenValidity());
                    client.setRefreshTokenValiditySeconds(clientDetails.getRefreshTokenValidity());
                    client.setClientSecret(clientDetails.getClientSecret());

                    return client;
                } else {
                    throw new ClientRegistrationException("No Client Details for client id");
                }
            } catch (IllegalArgumentException e) {
                throw new ClientRegistrationException("No Client Details for client id", e);
            }
        });
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(jwtSigningKey);
        return converter;
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }

}