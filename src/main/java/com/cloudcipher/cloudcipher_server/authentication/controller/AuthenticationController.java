package com.cloudcipher.cloudcipher_server.authentication.controller;

import com.cloudcipher.cloudcipher_server.authentication.model.CCUser;
import com.cloudcipher.cloudcipher_server.authentication.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
public class AuthenticationController {
    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/login")
    public @ResponseBody Map<String, Object> login(@RequestParam String username, @RequestParam String password) {
        Map<String, Object> response = new HashMap<>();
        try {
            CCUser user = authenticationService.login(username, password);
            response.put("token", user.getToken());
            response.put("username", user.getUsername());
        } catch (BadCredentialsException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
        return response;
    }

    @PostMapping("/register")
    public @ResponseBody Map<String, Object> register(@RequestParam String username, @RequestParam String password) {
        Map<String, Object> response = new HashMap<>();
        try {
            authenticationService.register(username, password);
            response.put("success", "Account created successfully");
        } catch (BadCredentialsException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
        return response;
    }

    @PostMapping("/key")
    public @ResponseBody Map<String, Object> addPublicKey(@RequestParam String username, @RequestParam String password, @RequestParam MultipartFile publicKey) {
        Map<String, Object> response = new HashMap<>();
        try {
            authenticationService.addPublicKey(username, password, publicKey);
            response.put("success", "Account created successfully");
        } catch (BadCredentialsException | IOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
        return response;
    }

    @PostMapping("/publickey")
    public @ResponseBody byte[] publicKey(@RequestParam String username, @RequestParam String token, @RequestParam String targetUsername) {
        try {
            return authenticationService.getPublicKey(username, token, targetUsername);
        } catch (BadCredentialsException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }
}
