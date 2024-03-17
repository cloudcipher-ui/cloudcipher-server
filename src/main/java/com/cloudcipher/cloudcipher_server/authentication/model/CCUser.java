package com.cloudcipher.cloudcipher_server.authentication.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.*;

@Generated
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Builder
public class CCUser {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;

    private String username;
    private String hashedPassword;
    private String token;

    public void setToken(String token) {
        this.token = token;
    }
}
