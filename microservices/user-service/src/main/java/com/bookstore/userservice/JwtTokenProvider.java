package com.bookstore.userservice;

import java.security.Key;
import java.sql.Date;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Secret;
import io.kubernetes.client.util.Config;
import jakarta.annotation.PostConstruct;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret.name:jwt-secret}")
    private String secretName;

    @Value("${jwt.secret.key:jwt-secret-key}")
    private String secretKey;

    @Value("${jwt.expiration:3600000}")
    private long validityInMs;

    private Key key;

    private final String namespace = System.getenv().getOrDefault("POD_NAMESPACE", "default");

    @PostConstruct
    protected void init() {
        try {
            // Init Kubernetes client using in-cluster config
            ApiClient client = Config.fromCluster();
            Configuration.setDefaultApiClient(client);
            CoreV1Api api = new CoreV1Api();

            String jwtSecretValue;

            try {
                // Try to fetch existing secret
                V1Secret existingSecret = api.readNamespacedSecret(secretName, namespace, null);
                byte[] secretBytes = existingSecret.getData().get(secretKey);
                jwtSecretValue = new String(secretBytes);
                System.out.println("Existing secret found and loaded.");
            } catch (ApiException e) {
                if (e.getCode() == 404) {
                    // Generate new secret
                    jwtSecretValue = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");

                    Map<String, byte[]> data = new HashMap<>();
                    data.put(secretKey, jwtSecretValue.getBytes());

                    V1Secret secret = new V1Secret()
                            .metadata(new V1ObjectMeta().name(secretName).namespace(namespace))
                            .type("Opaque")
                            .data(data);

                    api.createNamespacedSecret(namespace, secret, null, null, null, null);
                    System.out.println("New secret created in Kubernetes.");
                } else {
                    throw e;
                }
            }

            // Prepare signing key
            byte[] secretBytes = Base64.getEncoder().encode(jwtSecretValue.getBytes());
            this.key = Keys.hmacShaKeyFor(secretBytes);

        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException("Failed to initialize JwtTokenProvider", ex);
        }
    }

    public String createToken(String username) {
        Claims claims = Jwts.claims().setSubject(username);
        Date now = new Date(System.currentTimeMillis());
        Date validity = new Date(now.getTime() + validityInMs);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}

