package com.brainstorm.domain;

import lombok.Data;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Document(collection = "oauth_code")
@Data
public class OauthCode {

    @Id
    private ObjectId id;

    @Field(value = "code")
    private String code;

    @Field(value = "authentication")
    private byte[] authentication;
}