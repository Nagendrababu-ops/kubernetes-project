package com.bookstore.userservice;

import java.security.Key;
import java.sql.Date;
import java.util.Base64;

import javax.annotation.PostConstruct;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.*;
import io.kubernetes.client.util.Config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

    @Value("${jwt.expiration}")
    private long validityInMs;

    @Value("${jwt.k8s.secretName:user-service-secret}")
    private String secretName;

    @Value("${jwt.k8s.secretKey:jwt-secret}")
    private String secretKey;

    @Value("${jwt.k8s.namespace:user}")
    private String namespace;

    private Key key;

    @PostConstruct
    protected void init() {
        try {
            ApiClient client = Config.defaultClient(); // uses in-cluster config
            CoreV1Api api = new CoreV1Api(client);

            V1Secret secret;
            try {
                secret = api.readNamespacedSecret(secretName, namespace, null);
                byte[] decoded = Base64.getDecoder().decode(secret.getData().get(secretKey));
                this.key = Keys.hmacShaKeyFor(decoded);
                System.out.println("🔐 Loaded JWT key from Kubernetes Secret.");
            } catch (Exception e) {
                // Secret not found, generate new one
                this.key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
                byte[] encoded = Base64.getEncoder().encode(key.getEncoded());

                V1Secret newSecret = new V1Secret()
                        .metadata(new V1ObjectMeta()
                                .name(secretName)
                                .namespace(namespace))
                        .putDataItem(secretKey, encoded)
                        .type("Opaque");

                api.createNamespacedSecret(namespace, newSecret, null, null, null, null);
                System.out.println("✨ Generated new JWT key and stored it in Kubernetes Secret.");
            }
        } catch (Exception ex) {
            throw new RuntimeException("Failed to initialize JWT key from K8s", ex);
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

