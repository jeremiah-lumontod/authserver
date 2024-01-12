package com.anbu.authserver.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.Objects;

@Component
public class JWTTokenGeneratorFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(Objects.nonNull(authentication)){
            SecretKey key = Keys.hmacShaKeyFor("jxgEQeXHuPq8VdbyYFNkANdudQ53YUn4".getBytes(StandardCharsets.UTF_8));
            String jwt = Jwts.builder()
                    .setIssuer("OIDC Auth Server")
                    .setSubject("JWT Auth Token")
                    .claim("username", authentication.getName())
                    .claim("authorities", new ArrayList<String>())
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(new Date().getTime() + 3000000))
                    .signWith(key).compact();
            response.setHeader("Authorization", jwt);
        }
        filterChain.doFilter(request, response);
    }
}
