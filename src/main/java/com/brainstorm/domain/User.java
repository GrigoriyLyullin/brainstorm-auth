package com.brainstorm.domain;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.List;

@Document(collection = "users")
@Data
@NoArgsConstructor
public class User {

    @Id
    private ObjectId id;

    @Field(value = "username")
    private String username;

    @Field(value = "password")
    private String password;

    @Field(value = "enabled")
    private Boolean enabled;

    @DBRef
    private List<UserRole> roles;
}