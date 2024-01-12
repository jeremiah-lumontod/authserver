package com.anbu.authserver.repository;

import com.anbu.authserver.entity.PersistentLogin;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PersistentLoginRepository extends MongoRepository<PersistentLogin, String> {
    void deleteByUsername(String username);
}
