package com.brainstorm.domain;

import lombok.Data;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.Date;

@Document(collection = "oauth_client_details")
@Data
public class OauthClientDetails {

    @Id
    private ObjectId id;

    @Field(value = "client_id")
    private String clientId;

    @Field(value = "client_name")
    private String clientName;

    @Field(value = "resource_ids")
    private String resourceIds;

    @Field(value = "client_secret")
    private String clientSecret;

    @Field(value = "scope")
    private String scope;

    @Field(value = "authorized_grant_types")
    private String authorizedGrantTypes;

    @Field(value = "web_server_redirect_uri")
    private String webServerRedirectUri;

    @Field(value = "authorities")
    private String authorities;

    @Field(value = "access_token_validity")
    private Integer accessTokenValidity;

    @Field(value = "refresh_token_validity")
    private Integer refreshTokenValidity;

    @Field(value = "additional_information")
    private String additionalInformation;

    @Field(value = "autoapprove")
    private Integer autoApprove;

    @Field(value = "uuid")
    private String uuid;

    @Field(value = "created")
    private Date created;

    @Field(value = "enabled")
    private Boolean enabled;

    @Transient
    private String[] scopes;

    @Transient
    private String[] grantTypes;

    @Transient
    private String ownerEmail;
}
