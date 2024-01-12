package com.anbu.authserver.repository;

import ch.qos.logback.core.net.server.Client;
import com.anbu.authserver.entity.OAuth2RegisteredClient;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

@Service
@AllArgsConstructor
public class MongoRegisteredClientRepository implements RegisteredClientRepository {

    private OAuth2RegisteredClientRepository oAuth2RegisteredClientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        OAuth2RegisteredClient oAuth2RegisteredClient = OAuth2RegisteredClient.builder()
                .clientId(registeredClient.getClientId())
                .clientName(registeredClient.getClientName())
                .clientIdIssuedAt(registeredClient.getClientIdIssuedAt())
                .clientSecret(registeredClient.getClientSecret())
                .authorizationGrantTypes(registeredClient.getAuthorizationGrantTypes())
                .clientSecretExpiresAt(registeredClient.getClientSecretExpiresAt())
                //.clientSettings()
                .clientAuthenticationMethods(registeredClient.getClientAuthenticationMethods())
                .scopes(registeredClient.getScopes())
                .redirectUris(registeredClient.getRedirectUris())
                .postLogoutRedirectUris(registeredClient.getPostLogoutRedirectUris())
                .tokenSettings(registeredClient.getTokenSettings())
                .build();
        oAuth2RegisteredClientRepository.save(oAuth2RegisteredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        Optional<OAuth2RegisteredClient> byId = oAuth2RegisteredClientRepository.findById(id);
        if(!byId.isPresent())
            return null;
        return toRegisteredClient(byId.get());
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Optional<OAuth2RegisteredClient> byClientId = oAuth2RegisteredClientRepository.findByClientId(clientId);
        if(!byClientId.isPresent())
            return null;
        return toRegisteredClient(byClientId.get());
    }

    private RegisteredClient toRegisteredClient(OAuth2RegisteredClient oAuth2RegisteredClient){
        Consumer<Set<AuthorizationGrantType>> grantTypeConsumer = grantTypes-> oAuth2RegisteredClient.getAuthorizationGrantTypes().toArray();
        RegisteredClient.Builder builder = RegisteredClient.withId(oAuth2RegisteredClient.getId());
        return builder
                .clientId(oAuth2RegisteredClient.getClientId())
                .clientName(oAuth2RegisteredClient.getClientName())
                .clientIdIssuedAt(oAuth2RegisteredClient.getClientIdIssuedAt())
                .clientSecret(oAuth2RegisteredClient.getClientSecret())
                .authorizationGrantTypes(grantTypes-> grantTypes.addAll(oAuth2RegisteredClient.getAuthorizationGrantTypes()))
                .clientSecretExpiresAt(oAuth2RegisteredClient.getClientSecretExpiresAt())
                .clientSettings(ClientSettings
                        .builder()
                        .requireAuthorizationConsent(oAuth2RegisteredClient.getClientSettings().getOrDefault("requireAuthorizationConsent",false))
                        .requireProofKey(oAuth2RegisteredClient.getClientSettings().getOrDefault("requireProofKey",false))
                        .build())
                .clientAuthenticationMethods(authMethods-> authMethods.addAll(oAuth2RegisteredClient.getClientAuthenticationMethods()))
                .scopes(scopes-> scopes.addAll(oAuth2RegisteredClient.getScopes()))
                .redirectUris(redirect -> redirect.addAll(oAuth2RegisteredClient.getRedirectUris()))
                .postLogoutRedirectUris(logout-> logout.addAll(oAuth2RegisteredClient.getPostLogoutRedirectUris()))
                .tokenSettings(oAuth2RegisteredClient.getTokenSettings())
                .build();
    }
}
