package com.cloudcipher.cloudcipher_server.file.repository;

import com.cloudcipher.cloudcipher_server.authentication.model.CCUser;
import com.cloudcipher.cloudcipher_server.file.model.SharedFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SharedFileRepository extends JpaRepository<SharedFile, Integer> {

    boolean existsByShareId(String shareId);

    SharedFile findByShareId(String shareId);

    boolean existsByOwnerAndFilename(CCUser owner, String filename);

    SharedFile findByOwnerAndFilename(CCUser owner, String filename);
}
