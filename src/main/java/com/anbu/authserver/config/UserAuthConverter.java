package com.anbu.authserver.config;

import com.anbu.authserver.entity.AuthUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Converter used to obtain the credentials of each request made.
 * If no credentials are found in the request, null is returned as Authentication object in the SecurityContext.
 */
@Component
public class UserAuthConverter implements AuthenticationConverter {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    @Override
    public Authentication convert(HttpServletRequest request) {
        AuthUser userDto = null;
        try {
            userDto = MAPPER.readValue(request.getInputStream(), AuthUser.class);
        } catch (IOException e) {
            return null;
        }
        return UsernamePasswordAuthenticationToken.unauthenticated(userDto.username(), userDto.password());
    }
}
