package com.cloudcipher.cloudcipher_server.authentication.repository;

import com.cloudcipher.cloudcipher_server.authentication.model.CCUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CCUserRepository extends JpaRepository<CCUser, Integer> {

    CCUser findByUsername(String username);

    boolean existsCCUserByUsername(String username);

    boolean existsCCUserByToken(String token);
}