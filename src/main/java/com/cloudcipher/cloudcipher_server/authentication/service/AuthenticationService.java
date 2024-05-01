package com.cloudcipher.cloudcipher_server.authentication.service;

import com.cloudcipher.cloudcipher_server.authentication.model.CCUser;
import com.cloudcipher.cloudcipher_server.authentication.repository.CCUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
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

    @Transactional
    public void addPublicKey(String username, String password, MultipartFile publicKey) throws IOException {
        CCUser user = CCUserRepository.findByUsername(username);
        if (user == null || !passwordEncoder.matches(password, user.getHashedPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }

        user.setPublicKey(publicKey.getBytes());
        CCUserRepository.save(user);
    }

    public CCUser login(String username, String password) {
        CCUser user = CCUserRepository.findByUsername(username);
        if (user == null || !passwordEncoder.matches(password, user.getHashedPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }

        user.setToken(generateToken());
        CCUserRepository.save(user);

        return user;
    }

    public boolean isNotAuthorized(String expectedUsername, String token) {
        CCUser user = CCUserRepository.findByUsername(expectedUsername);
        if (user == null || token == null) {
            return true;
        }

        return !user.getToken().equals(token);
    }

    private String generateToken() {
        final String chrs = "0123456789abcdefghijklmnopqrstuvwxyz-_ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            return "1234567890";
        }

        String token = secureRandom
                .ints(TOKEN_LENGTH, 0, chrs.length())
                .mapToObj(chrs::charAt)
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();

        while (CCUserRepository.existsCCUserByToken(token)) {
            token = secureRandom
                    .ints(TOKEN_LENGTH, 0, chrs.length())
                    .mapToObj(chrs::charAt)
                    .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                    .toString();
        }

        return token;
    }

    public byte[] getPublicKey(String username, String token, String targetUsername) {
        CCUser user = CCUserRepository.findByUsername(username);
        if (user == null || !user.getToken().equals(token)) {
            throw new BadCredentialsException("Invalid username or token");
        }

        CCUser targetUser = CCUserRepository.findByUsername(targetUsername);
        if (targetUser == null) {
            throw new BadCredentialsException("Target user does not exist");
        }

        byte[] k = targetUser.getPublicKey();
        return k;
    }

    public boolean userExists(String username) {
        return CCUserRepository.existsCCUserByUsername(username);
    }
}
