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
import java.util.List;
import java.util.function.Function;

/**
 * Utility class for handling JWT operations such as generating and validating tokens.
 * @author Matushkin Anton
 */
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

    /**
     * Extracts the username from the given token.
     * @param token The token.
     * @return The username.
     */
    public String getUsernameFromToken(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    /**
     * Extracts the roles from the given token.
     * @param token The token.
     * @return list of roles.
     */
    public List<String> getRolesFromToken(String token) {
        if (isTokenExpired(token)) {
            return null;
        } else {
            return extractClaims(token, claims -> claims.get("roles", List.class));
        }

    }

    /**
     * Checks if the given token is expired.
     * @param token The token.
     * @return True if the token is expired, false otherwise.
     */
    public boolean isTokenExpired(String token) {
        try {
            return extractClaims(token, Claims::getExpiration).before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    /**
     * Extracts claims from the given token using the provided function.
     * @param token The token.
     * @param claimsTFunction The function to apply on the claims.
     * @param <T> The type of the claim.
     * @return The extracted claim.
     */
    private <T> T extractClaims(String token, Function<Claims, T> claimsTFunction) throws ExpiredJwtException {
            return claimsTFunction.apply(Jwts
                    .parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token.substring(7))
                    .getPayload());

    }

}
