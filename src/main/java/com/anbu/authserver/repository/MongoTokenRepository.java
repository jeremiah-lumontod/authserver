package com.anbu.authserver.repository;

import com.anbu.authserver.entity.PersistentLogin;
import lombok.AllArgsConstructor;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;

@Repository
@AllArgsConstructor
public class MongoTokenRepository implements PersistentTokenRepository {

    private final PersistentLoginRepository persistentLoginRepository;

    @Override
    public void createNewToken(PersistentRememberMeToken token) {
        persistentLoginRepository.save(PersistentLogin.builder()
                        .token(token.getTokenValue())
                        .username(token.getUsername())
                        .series(token.getSeries())
                        .last_used(token.getDate())
                .build());

    }

    @Override
    public void updateToken(String series, String tokenValue, Date lastUsed) {
        Optional<PersistentLogin> byId = persistentLoginRepository.findById(series);
        persistentLoginRepository.save(PersistentLogin.builder()
                .token(tokenValue)
                .username(byId.get().getUsername())
                .series(series)
                .last_used(lastUsed)
                .build());
    }

    @Override
    public PersistentRememberMeToken getTokenForSeries(String seriesId) {
        Optional<PersistentLogin> byId = persistentLoginRepository.findById(seriesId);
        return new PersistentRememberMeToken(byId.get().getUsername(),
                byId.get().getSeries(),
                byId.get().getToken(),
                byId.get().getLast_used());
    }

    @Override
    public void removeUserTokens(String username) {
        persistentLoginRepository.deleteByUsername(username);
    }
}
