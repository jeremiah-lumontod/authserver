package com.anbu.authserver.config;

import com.anbu.authserver.entity.AuthUser;
import com.anbu.authserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.nio.CharBuffer;
import java.util.Collections;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class UserAuthProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String login = authentication.getName();
        String password = authentication.getCredentials().toString();

        Optional<AuthUser> oUser = userRepository.findByUsername(login);

        if (oUser.isEmpty()) {
            throw new BadCredentialsException("User not Found");
        }

        AuthUser user = oUser.get();

        if (passwordEncoder.matches(CharBuffer.wrap(password), user.password())) {
            UsernamePasswordAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(login, password, Collections.emptyList());
            return authenticated;
        }else{
            throw new BadCredentialsException("Invalid Password");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
