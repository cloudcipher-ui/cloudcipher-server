package com.cloudcipher.cloudcipher_server.utility;

import org.apache.coyote.BadRequestException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

public class WebUtility {



    private static CloseableHttpClient createClient() {
        try {
            TrustStrategy acceptingTrustStrategy = (cert, authType) -> true;
            SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext,
                    NoopHostnameVerifier.INSTANCE);

            Registry<ConnectionSocketFactory> socketFactoryRegistry =
                    RegistryBuilder.<ConnectionSocketFactory>create()
                            .register("https", sslsf)
                            .register("http", new PlainConnectionSocketFactory())
                            .build();

            BasicHttpClientConnectionManager connectionManager =
                    new BasicHttpClientConnectionManager(socketFactoryRegistry);

            return HttpClients.custom().setSSLSocketFactory(sslsf).setConnectionManager(connectionManager).build();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] initiateReEncryption(String url, String secretKey, String filename, byte[] fileBytes, byte[] iv, String rg) {
        HttpPost post = new HttpPost(url);
        HttpEntity entity = MultipartEntityBuilder.create()
                .addBinaryBody("file", fileBytes, ContentType.APPLICATION_OCTET_STREAM, filename)
                .addBinaryBody("iv", iv, ContentType.APPLICATION_OCTET_STREAM, "iv")
                .addTextBody("rg", rg)
                .addTextBody("key", secretKey)
                .build();
        post.setEntity(entity);

        try (CloseableHttpClient client = createClient()) {
            HttpResponse response = client.execute(post);
            HttpEntity responseEntity = response.getEntity();

            if (response.getStatusLine().getStatusCode() != 200) {
                throw new BadRequestException("Error re-encrypting file.");
            }

            if (responseEntity == null) {
                throw new RuntimeException("Internal server error. Please try again later or contact support");
            }

            return responseEntity.getContent().readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
