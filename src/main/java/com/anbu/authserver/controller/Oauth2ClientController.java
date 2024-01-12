package com.anbu.authserver.controller;

import com.anbu.authserver.entity.OAuth2RegisteredClient;
import com.anbu.authserver.repository.OAuth2RegisteredClientRepository;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAmount;
import java.time.temporal.TemporalUnit;

@RestController
@RequestMapping("/client")
@AllArgsConstructor
public class Oauth2ClientController {

    private final OAuth2RegisteredClientRepository auth2RegisteredClientRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity registerClient(@RequestBody OAuth2RegisteredClient oAuth2RegisteredClient){
        try{
            oAuth2RegisteredClient.setClientIdIssuedAt(Instant.now());
            oAuth2RegisteredClient.setClientSecretExpiresAt(Instant.now().plus(99, ChronoUnit.DAYS));
            oAuth2RegisteredClient.setClientSecret(passwordEncoder.encode(oAuth2RegisteredClient.getClientSecret()));
            OAuth2RegisteredClient registeredClient = auth2RegisteredClientRepository.save(oAuth2RegisteredClient);
            return ResponseEntity.ok(HttpStatus.CREATED+"--"+registeredClient);
        } catch (Exception e){
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Error while creating the client");
        }
    }
}
