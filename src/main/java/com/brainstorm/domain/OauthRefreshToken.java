package com.brainstorm.domain;

import lombok.Data;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Document(collection = "oauth_refresh_token")
@Data
public class OauthRefreshToken {

    @Id
    private ObjectId id;

    @Field(value = "token_id")
    private String tokenId;

    @Field(value = "token")
    private byte[] token;

    @Field(value = "token_authentication")
    private byte[] authentication;
}


