package com.brainstorm.changelogs;

import com.github.cloudyrock.mongock.ChangeLog;
import com.github.cloudyrock.mongock.ChangeSet;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;

import java.util.Arrays;
import java.util.Collections;

@ChangeLog
public class DatabaseChangeLog {

    @ChangeSet(order = "001", id = "clean", author = "Grigorii Liullin", runAlways = true)
    public void clean(MongoDatabase db) {
        db.drop();
    }

    @ChangeSet(order = "002", id = "importInitialClientAndUser", author = "Grigorii Liullin")
    public void importSomeInitialData(MongoDatabase db) {
        Document clientDetailsDocument = new Document()
                .append("client_id", "brainstorm-jwt-client")
                .append("resource_ids", "brainstorm-oauth2-server")
                // admin
                .append("client_secret", "$2a$04$Fx9v2ZGKGFCRFWdoSI.yReL/ImkTjQWFMeiZUECPMGQhvyYaZ0cHm")
                .append("scope", "read,write")
                .append("authorized_grant_types", "password,authorization_code,refresh_token,implicit")
                .append("authorities", "USER")
                .append("access_token_validity", 10800)
                .append("refresh_token_validity", 86400);

        db.getCollection("oauth_client_details").insertOne(clientDetailsDocument);

        Document admin = new Document()
                .append("username", "admin")
                // password is 'admin'
                .append("password", "$2a$04$Fx9v2ZGKGFCRFWdoSI.yReL/ImkTjQWFMeiZUECPMGQhvyYaZ0cHm")
                .append("enabled", true)
                .append("roles", Arrays.asList(new Document().append("name", "ROLE_ADMIN"),
                        new Document().append("name", "ROLE_USER")));

        Document user = new Document()
                .append("username", "user")
                // password is 'password'
                .append("password", "$2a$04$HMby.2tPbO0PNewU4oBXme7BJexhjrOkFGa43xvsOUSlFI01kM4Ki")
                .append("enabled", true)
                .append("roles", Collections.singletonList(new Document().append("name", "ROLE_USER")));

        db.getCollection("users").insertMany(Arrays.asList(admin, user));
    }
}
