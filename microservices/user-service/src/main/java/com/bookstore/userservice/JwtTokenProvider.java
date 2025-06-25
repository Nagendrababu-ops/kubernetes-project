package com.bookstore.userservice;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.*;
import io.kubernetes.client.util.Config;
import jakarta.annotation.PostConstruct;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Component
public class JwtTokenProvider {

    private String jwtSecret;
    private final long jwtExpirationInMs = 3600000; // 1 hour

    @PostConstruct
    public void init() {
        try {
            ApiClient client = Config.defaultClient();
            Configuration.setDefaultApiClient(client);
            CoreV1Api api = new CoreV1Api(client);

            String namespace = Files.readString(Path.of("/var/run/secrets/kubernetes.io/serviceaccount/namespace")).trim();
            String secretName = "user-service-jwt-secret";

            V1Secret existingSecret = api.readNamespacedSecret(secretName, namespace, null);
            byte[] secretBytes = Base64.getDecoder().decode(existingSecret.getData().get("jwt-secret"));
            this.jwtSecret = new String(secretBytes, StandardCharsets.UTF_8);

            System.out.println("✅ Loaded JWT secret from Kubernetes secret.");

        } catch (ApiException e) {
            if (e.getCode() == 404) {
                System.out.println("🔐 Secret not found. Generating new one...");
                this.jwtSecret = generateSecret();
                createSecretInKubernetes(this.jwtSecret);
            } else {
                throw new RuntimeException("❌ Failed to read secret from Kubernetes", e);
            }
        } catch (IOException e) {
            throw new RuntimeException("❌ Failed to read namespace", e);
        }
    }

    private String generateSecret() {
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    private void createSecretInKubernetes(String secretValue) {
        try {
            CoreV1Api api = new CoreV1Api();
            String namespace = Files.readString(Path.of("/var/run/secrets/kubernetes.io/serviceaccount/namespace")).trim();
            String secretName = "user-service-jwt-secret";

            Map<String, byte[]> data = Map.of(
                    "jwt-secret", Base64.getEncoder().encode(secretValue.getBytes(StandardCharsets.UTF_8))
            );

            V1Secret secret = new V1Secret()
                    .metadata(new V1ObjectMeta().name(secretName).namespace(namespace))
                    .type("Opaque")
                    .data(data);

            api.createNamespacedSecret(namespace, secret, null, null, null, null);
            System.out.println("✅ Created new JWT secret in Kubernetes.");

        } catch (Exception e) {
            throw new RuntimeException("❌ Failed to create secret in Kubernetes", e);
        }
    }

    public String generateToken(Authentication authentication) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(jwtSecret)), SignatureAlgorithm.HS256)
                .compact();
    }

    // NEW: Used by controller
    public String createToken(String username) {
        Authentication auth = new UsernamePasswordAuthenticationToken(username, null, null);
        return generateToken(auth);
    }

    // Renamed to match usage in JwtAuthenticationFilter
    public String getUsername(String token) {
        return getUsernameFromJWT(token);
    }

    public String getUsernameFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(Base64.getDecoder().decode(jwtSecret)))
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(Base64.getDecoder().decode(jwtSecret)))
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            System.err.println("❌ Invalid JWT: " + e.getMessage());
            return false;
        }
    }
}
