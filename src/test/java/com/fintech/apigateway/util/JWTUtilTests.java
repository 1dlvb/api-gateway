package com.fintech.apigateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JWTUtilTests {

    @Mock
    private SecretKey key;

    @InjectMocks
    private JWTUtil jwtUtil;

    private String token;

    @BeforeEach
    void setUp() {
        String secret = "a8da42da478c2d6be0582d902fc7efb3aea43cd9eb1f5c3fe3aeb45695421942";
        byte[] secretBytes = Base64.getDecoder().decode(secret.getBytes(StandardCharsets.UTF_8));
        String algorithm = "HmacSHA256";
        this.key = new SecretKeySpec(secretBytes, algorithm);

        ReflectionTestUtils.setField(jwtUtil, "secret", secret);
        ReflectionTestUtils.setField(jwtUtil, "algorithm", algorithm);

        ReflectionTestUtils.invokeMethod(jwtUtil, "init");

        Claims claims = Jwts.claims().subject("test")
                .add("roles", List.of("USER"))
                .build();
        this.token = Jwts.builder()
                .claims(claims)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 10000))
                .signWith(key)
                .compact();

    }
    @Test
    void testGetUsernameFromTokenReturnsUsername() {
        String username = jwtUtil.getUsernameFromToken("Bearer " + token);
        assertEquals("test", username);
    }

    @Test
    void testGetRolesFromTokenReturnsRoles() {
        List<String> roles = jwtUtil.getRolesFromToken("Bearer " + token);
        assertNotNull(roles);
        assertEquals(1, roles.size());
        assertEquals("USER", roles.get(0));
    }

    @Test
    void testIsTokenExpired() {
        assertFalse(jwtUtil.isTokenExpired("Bearer " + token));

        Claims claims = Jwts.claims().subject("test").build();
        String expiredToken = Jwts.builder()
                .claims(claims)
                .claim("roles", List.of("USER"))
                .issuedAt(new Date(System.currentTimeMillis() - 20000))
                .expiration(new Date(System.currentTimeMillis() - 1000))
                .signWith(key)
                .compact();

        assertTrue(jwtUtil.isTokenExpired("Bearer " + expiredToken));
    }

}
