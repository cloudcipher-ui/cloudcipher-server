package com.cloudcipher.cloudcipher_server.file;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

@Configuration
public class S3Config {

    @Value("${aws.access-key}")
    private String accessKey;

    @Value("${aws.secret-key}")
    private String secretKey;

    @Value("${aws.session-token:#{null}}")
    private String sessionToken;

    @Value("${aws.region}")
    private String region;

    @Bean
    public S3Client s3Client() {
        AwsCredentials awsCredentials;
        if (sessionToken != null) {
            awsCredentials = AwsSessionCredentials.create(accessKey, secretKey, sessionToken);
        } else {
            awsCredentials = AwsBasicCredentials.create(accessKey, secretKey);
        }

        return S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(awsCredentials))
                .region(Region.of(region))
                .build();
    }
}
