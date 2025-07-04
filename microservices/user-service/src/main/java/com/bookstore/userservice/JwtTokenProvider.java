package com.bookstore.userservice;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;
    @Value("${jwt.expiration}")
    private long jwtExpiration;

    public String createToken(String username) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpiration);

        return Jwts.builder()
                   .setSubject(username)
                   .setIssuedAt(now)
                   .setExpiration(expiry)
                   .signWith(SignatureAlgorithm.HS512, jwtSecret)
                   .compact();
    }

    public String getUsername(String token) {
        return Jwts.parser()
                   .setSigningKey(jwtSecret)
                   .parseClaimsJws(token)
                   .getBody()
                   .getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }
}
