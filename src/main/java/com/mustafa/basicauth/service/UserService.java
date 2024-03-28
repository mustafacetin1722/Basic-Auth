package com.mustafa.basicauth.service;

import com.mustafa.basicauth.dto.CreateUserRequest;
import com.mustafa.basicauth.model.User;
import com.mustafa.basicauth.repositroy.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Optional<User> getByUsername(String username){
        return this.userRepository.findByUsername(username);
    }

    public User createUser(CreateUserRequest userRequest){
        User newUser = User.builder()
                .name(userRequest.name())
                .username(userRequest.username())
                .password(passwordEncoder.encode(userRequest.password()))
                .authorities(userRequest.authorities())
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .isEnabled(true)
                .build();
        return this.userRepository.save(newUser);
    }


}
