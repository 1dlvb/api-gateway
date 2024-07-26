package com.fintech.apigateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

@Component
public class JWTUtil {

    private SecretKey key;

    @Value("${jwt.secret.string}")
    private String secret;

    @Value("${jwt.secret.algorithm}")
    private String algorithm;

    @PostConstruct
    private void init() {
        byte[] secretBytes = Base64.getDecoder().decode(secret.getBytes(StandardCharsets.UTF_8));
        this.key = new SecretKeySpec(secretBytes, algorithm);
    }

    public String getUsernameFromToken(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    public String getRoleFromToken(String token) {
        if (isTokenExpired(token)) {
            return null;
        } else {
            return extractClaims(token, claims -> claims.get("role", String.class));
        }

    }

    public boolean isTokenExpired(String token) {
        try {
            return extractClaims(token, Claims::getExpiration).before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    private <T> T extractClaims(String token, Function<Claims, T> claimsTFunction) throws ExpiredJwtException {
            return claimsTFunction.apply(Jwts
                    .parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token.substring(7))
                    .getPayload());

    }

}
