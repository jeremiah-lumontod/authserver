package com.anbu.authserver.service;

import com.anbu.authserver.entity.AuthUser;
import com.anbu.authserver.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthServerUserDetailsService implements UserDetailsService {


    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<AuthUser> authUser = userRepository.findByUsername(username);
        if (!authUser.isPresent()) {
            throw new UsernameNotFoundException(username);
        } else {
            return User.builder()
                    .username(authUser.get().username())
                    .password(authUser.get().password())
                    .disabled(!authUser.get().active())
                    .build();

        }
    }
}
