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
import org.springframework.web.server.ResponseStatusException;

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
}
