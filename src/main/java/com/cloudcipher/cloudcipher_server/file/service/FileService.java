package com.cloudcipher.cloudcipher_server.file.service;

import com.cloudcipher.cloudcipher_server.authentication.service.AuthenticationService;
import org.apache.coyote.BadRequestException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class FileService {

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private S3Client s3Client;

    @Value("${aws.bucket-name}")
    private String bucketName;

    @Value("${secret-key}")
    private String secretKey;

    @Value("${proxy-url}")
    private String proxyUrl;

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
                    PutObjectRequest.builder()
                            .bucket(bucketName)
                            .key(key)
                            .build(),
                    RequestBody.fromBytes(fileBytes)
            );
        } catch (S3Exception e) {
            throw new BadRequestException("Error uploading file to S3.");
        }
    }

    private byte[] downloadFromS3(String key) throws BadRequestException {
        try {
            ResponseBytes<GetObjectResponse> response = s3Client.getObjectAsBytes(
                    GetObjectRequest
                            .builder()
                            .key(key)
                            .bucket(bucketName)
                            .build()
            );
            return response.asByteArray();
        } catch (NoSuchKeyException e) {
            throw new BadRequestException("File not found.");
        }
    }

    private void deleteFromS3(String key) throws BadRequestException {
        try {
            s3Client.deleteObject(builder -> builder.bucket(bucketName).key(key));
        } catch (NoSuchKeyException e) {
            throw new BadRequestException("File not found.");
        }
    }

    public void upload(String username, String token, MultipartFile file, MultipartFile iv) throws BadRequestException {
        if (authenticationService.isNotAuthorized(username, token)) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        try {
            byte[] fileBytes = file.getBytes();
            String key = username + "/" + file.getOriginalFilename();
            String noWhiteSpaceKey = key.replaceAll("\\s", "_");
            uploadToS3(noWhiteSpaceKey, fileBytes);

            byte[] ivBytes = iv.getBytes();
            String ivKey = username + "/iv/" + file.getOriginalFilename();
            String noWhiteSpaceIvKey = ivKey.replaceAll("\\s", "_");
            uploadToS3(noWhiteSpaceIvKey, ivBytes);
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

        String ivKey = username + "/iv/" + filename;
        deleteFromS3(ivKey);
    }

    public void reEncrypt(String username, String targetUsername, String token, String filename, MultipartFile rg) throws IOException {
        if (authenticationService.isNotAuthorized(username, token)) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        if (!authenticationService.userExists(targetUsername)) {
            throw new BadRequestException("Target user does not exist.");
        }

        String key = username + "/" + filename;
        if (!fileExistInS3(key)) {
            throw new BadRequestException("File not found.");
        }
        byte[] fileBytes = downloadFromS3(key);
        byte[] iv = downloadFromS3(username + "/iv/" + filename);

        HttpPost post = new HttpPost(proxyUrl);
        HttpEntity entity = MultipartEntityBuilder.create()
                .addBinaryBody("file", fileBytes, org.apache.http.entity.ContentType.DEFAULT_BINARY, filename)
                .addBinaryBody("iv", iv, org.apache.http.entity.ContentType.DEFAULT_BINARY, "iv")
                .addBinaryBody("rg", rg.getBytes(), org.apache.http.entity.ContentType.DEFAULT_BINARY, "rg")
                .addTextBody("key", secretKey)
                .build();

        post.setEntity(entity);
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpResponse response = client.execute(post);
            HttpEntity responseEntity = response.getEntity();

            if (response.getStatusLine().getStatusCode() != 200) {
                throw new BadRequestException("Error re-encrypting file.");
            }

            if (responseEntity == null) {
                throw new RuntimeException("Internal server error. Please try again later or contact support");
            }

            byte[] newFile = responseEntity.getContent().readAllBytes();
            uploadToS3(targetUsername + "/shared/" + username + "/" + filename, newFile);
            uploadToS3(targetUsername + "/shared/" + username + "/iv/" + filename, iv);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public List<Map<String, String>> list(String username, String token) {
        if (authenticationService.isNotAuthorized(username, token)) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        List<Map<String, String>> files = new ArrayList<>();
        String prefix = username + "/";

        ListObjectsV2Request listObjectsV2Request = ListObjectsV2Request.builder().bucket(bucketName).prefix(prefix).build();
        ListObjectsV2Response listObjectsV2Response = s3Client.listObjectsV2(listObjectsV2Request);
        for (S3Object s3Object : listObjectsV2Response.contents()) {
            String key = s3Object.key();
            if (key.contains("/iv/")) {
                continue;
            }
            String fileName = key.substring(prefix.length());
            long size = s3Object.size();
            files.add(Map.of("filename", fileName, "size", String.valueOf(size)));
        }

        return files;
    }

    public void newKey(String username, String token, String targetUsername, String filename, MultipartFile newKey) throws IOException {
        if (authenticationService.isNotAuthorized(username, token)) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        if (!authenticationService.userExists(targetUsername)) {
            throw new BadRequestException("Target user does not exist.");
        }

        uploadToS3(targetUsername + "/shared/" + username + "/key/" + filename + ".key", newKey.getBytes());
    }
}
