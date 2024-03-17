package com.cloudcipher.cloudcipher_server.authentication.service;

import com.cloudcipher.cloudcipher_server.authentication.model.CCUser;
import com.cloudcipher.cloudcipher_server.authentication.repository.CCUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Service
public class AuthenticationService {
    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private static final int TOKEN_LENGTH = 10;

    @Autowired
    private CCUserRepository CCUserRepository;

    @Transactional
    public void register(String username, String password) {
        if (CCUserRepository.existsCCUserByUsername(username)) {
            throw new BadCredentialsException("An account with that username already exists");
        }

        CCUser user = CCUser.builder()
                .username(username)
                .hashedPassword(passwordEncoder.encode(password))
                .build();
        CCUserRepository.save(user);
    }

    public CCUser login(String username, String password) {
        CCUser CCUser = CCUserRepository.findByUsername(username);
        if (CCUser == null || !passwordEncoder.matches(password, CCUser.getHashedPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }

        String randomToken = generateToken();
        while (CCUserRepository.existsCCUserByToken(randomToken)) {
            randomToken = generateToken();
        }

        CCUser.setToken(randomToken);
        CCUserRepository.save(CCUser);

        return CCUser;
    }

    public boolean isNotAuthorized(String expectedUsername, String token) {
        CCUser CCUser = CCUserRepository.findByUsername(expectedUsername);
        if (CCUser == null || token == null) {
            return true;
        }

        return !CCUser.getToken().equals(token);
    }

    private String generateToken() {
        final String chrs = "0123456789abcdefghijklmnopqrstuvwxyz-_ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            return "1234567890";
        }

        return secureRandom
                .ints(TOKEN_LENGTH, 0, chrs.length())
                .mapToObj(chrs::charAt)
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();
    }
}
