package com.traineeship.auth_service.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secretBase64;

    @Value("${jwt.expiration-ms:3600000}")
    private long validityInMilliseconds;

    private Key key;

    @PostConstruct
    public void init() {
        try {
            byte[] decoded = Base64.getDecoder().decode(secretBase64);
            this.key = Keys.hmacShaKeyFor(decoded);
        } catch (IllegalArgumentException e) {
            byte[] bytes = secretBase64.getBytes(StandardCharsets.UTF_8);
            this.key = Keys.hmacShaKeyFor(bytes);
        }
    }

    public String generateToken(String username) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }


}
