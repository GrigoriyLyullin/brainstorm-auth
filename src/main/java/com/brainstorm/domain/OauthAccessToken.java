package com.brainstorm.domain;

import lombok.Data;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Document(collection = "oauth_access_token")
@Data
public class OauthAccessToken {

    @Id
    private ObjectId id;

    @Field(value = "token_id")
    private String tokenId;

    @Field(value = "token")
    private byte[] token;

    @Field(value = "authentication_id")
    private String authenticationId;

    @Field(value = "user_name")
    private String userName;

    @Field(value = "client_id")
    private String clientId;


    @Field(value = "authentication")
    private byte[] authentication;

    @Field(value = "refresh_token")
    private String refreshToken;
}