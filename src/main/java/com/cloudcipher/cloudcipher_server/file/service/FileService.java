package com.cloudcipher.cloudcipher_server.file.service;

import com.cloudcipher.cloudcipher_server.authentication.service.AuthenticationService;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.io.IOException;
import java.net.URI;
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
            s3Client.putObject(builder -> builder.bucket(bucketName).key(key).build(), RequestBody.fromBytes(fileBytes));
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

    public void reEncrypt(String username, String targetUsername, String token, String filename, MultipartFile iv, MultipartFile rg) throws IOException {
        if (authenticationService.isNotAuthorized(username, token)) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        String key = username + "/" + filename;
        if (!fileExistInS3(key)) {
            throw new BadRequestException("File not found.");
        }
        byte[] fileBytes = downloadFromS3(key);

        ByteArrayResource fileStream = new ByteArrayResource(fileBytes) {
            @Override
            public String getFilename() {
                return filename;
            }
        };
        ByteArrayResource ivStream = new ByteArrayResource(iv.getBytes()) {
            @Override
            public String getFilename() {
                return "iv";
            }
        };
        ByteArrayResource rgStream = new ByteArrayResource(rg.getBytes()) {
            @Override
            public String getFilename() {
                return "rg";
            }
        };

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", fileStream);
        body.add("iv", ivStream);
        body.add("rg", rgStream);
        body.add("key", secretKey);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

        URI uri = URI.create(proxyUrl);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<byte[]> response = restTemplate.postForEntity(uri, request, byte[].class);

        byte[] responseBody = response.getBody();
        if (responseBody == null) {
            throw new BadRequestException("Error re-encrypting file.");
        }

        String targetKey = targetUsername + "/shared/" + username + "/" + filename;
        uploadToS3(targetKey, responseBody);
    }

    public List<Map<String, String>> list(String username, String token) {
        if (authenticationService.isNotAuthorized(username, token)) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        List<Map<String, String>> files = new ArrayList<>();
        String prefix = username + "/";
        ListObjectsResponse response = s3Client.listObjects(
                ListObjectsRequest.builder().bucket(bucketName).prefix(prefix).build()
        );

        response.contents().forEach(object -> {
            String key = object.key();
            files.add(Map.of(
                    "filename", key.substring(prefix.length()),
                    "size", String.valueOf(object.size())
            ));
        });

        return files;
    }
}
