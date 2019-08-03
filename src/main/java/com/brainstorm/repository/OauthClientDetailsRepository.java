package com.brainstorm.repository;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
import com.brainstorm.domain.OauthClientDetails;

public interface OauthClientDetailsRepository extends MongoRepository<OauthClientDetails, ObjectId> {

    OauthClientDetails findByClientId(String clientId);
}
