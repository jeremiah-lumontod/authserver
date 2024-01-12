package com.anbu.authserver.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Document("OAuthUser")
public record AuthUser(@Id String id, @Indexed String username, String password, String firstName, String lastName, boolean active) {

    public AuthUser withPassword(String password){
        return new AuthUser(id(), username(), password, firstName(), lastName(), active());
    }
}
