package com.cloudcipher.cloudcipher_server.file.model;

import com.cloudcipher.cloudcipher_server.authentication.model.CCUser;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SharedFile {

    @Id
    private String shareId;

    private String filename;
    private String filePath;
    private String ivPath;

    @ManyToOne(fetch = FetchType.LAZY)
    private CCUser owner;
}
