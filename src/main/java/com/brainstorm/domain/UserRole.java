package com.brainstorm.domain;

import lombok.Data;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Field;

@Data
public class UserRole {

    @Id
    private ObjectId id;

    @Field(value = "name")
    private String name;

}