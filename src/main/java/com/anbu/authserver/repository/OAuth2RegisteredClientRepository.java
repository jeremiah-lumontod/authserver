package com.anbu.authserver.repository;

import com.anbu.authserver.entity.OAuth2RegisteredClient;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
public interface OAuth2RegisteredClientRepository extends MongoRepository<OAuth2RegisteredClient, String> {
    Optional<OAuth2RegisteredClient> findByClientId(String clientId);
}
