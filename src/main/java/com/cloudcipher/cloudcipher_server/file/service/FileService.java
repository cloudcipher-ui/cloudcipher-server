package com.cloudcipher.cloudcipher_server.file.service;

import com.cloudcipher.cloudcipher_server.authentication.service.AuthenticationService;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.io.IOException;

@Service
public class FileService {

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private S3Client s3Client;

    @Value("${aws.bucket-name}")
    private String bucketName;

    private final String BAD_CREDENTIALS_MESSAGE = "Invalid credentials. Please login again";


    private boolean fileExistInS3(String key) {
        try {
            s3Client.headObject(builder -> builder.bucket(bucketName).key(key));
            return true;
        } catch (NoSuchKeyException e) {
            return false;
        }
    }

    private void uploadToS3(String key, byte[] fileBytes) throws BadRequestException {
        try {
            s3Client.putObject(
                    builder -> builder
                            .bucket(bucketName)
                            .key(key)
                            .build(), RequestBody.fromBytes(fileBytes)
            );
        } catch (S3Exception e) {
            throw new BadRequestException("Error uploading file to S3.");
        }
    }

    private byte[] downloadFromS3(String key) throws BadRequestException {
        try {
            return s3Client.getObject(
                    builder -> builder
                            .bucket(bucketName)
                            .key(key)).readAllBytes();
        } catch (NoSuchKeyException e) {
            throw new BadRequestException("File not found.");
        } catch (IOException e) {
            throw new RuntimeException("Error reading file bytes.");
        }
    }

    private void deleteFromS3(String key) throws BadRequestException {
        try {
            s3Client.deleteObject(builder -> builder.bucket(bucketName).key(key));
        } catch (NoSuchKeyException e) {
            throw new BadRequestException("File not found.");
        }
    }


    public void upload(String username, String token, MultipartFile file) throws BadRequestException {
        if (authenticationService.isNotAuthorized(username, token)) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        try {
            byte[] fileBytes = file.getBytes();
            String key = username + "/" + file.getOriginalFilename();
            String noWhiteSpaceKey = key.replaceAll("\\s", "_");
            uploadToS3(noWhiteSpaceKey, fileBytes);
        } catch (Exception e) {
            throw new BadRequestException("Error uploading file.");
        }
    }

    public byte[] download(String username, String token, String filename) throws BadRequestException {
        if (authenticationService.isNotAuthorized(username, token)) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        String key = username + "/" + filename;
        return downloadFromS3(key);
    }

    public void delete(String username, String token, String filename) throws BadRequestException {
        if (authenticationService.isNotAuthorized(username, token)) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        String key = username + "/" + filename;
        deleteFromS3(key);
    }
}
