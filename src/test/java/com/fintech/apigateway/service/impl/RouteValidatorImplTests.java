package com.fintech.apigateway.service.impl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class RouteValidatorImplTests {

    private RouteValidatorImpl routeValidator;

    @BeforeEach
    void setUp() {
        routeValidator = new RouteValidatorImpl();
    }

    @Test
    void testOpenEndpointSignin() {
        ServerHttpRequest request = MockServerHttpRequest.get("/auth/signin").build();
        Predicate<ServerHttpRequest> isSecured = routeValidator.isSecured();
        assertFalse(isSecured.test(request));
    }

    @Test
    void testOpenEndpointSignup() {
        ServerHttpRequest request = MockServerHttpRequest.get("/auth/signup").build();
        Predicate<ServerHttpRequest> isSecured = routeValidator.isSecured();
        assertFalse(isSecured.test(request));
    }

    @Test
    void testOpenEndpointRefreshToken() {
        ServerHttpRequest request = MockServerHttpRequest.get("/auth/refresh-token").build();
        Predicate<ServerHttpRequest> isSecured = routeValidator.isSecured();
        assertFalse(isSecured.test(request));
    }

    @Test
    void testSecuredEndpointWhenSecuredEndpoint() {
        ServerHttpRequest request = MockServerHttpRequest.get("/secured/endpoint").build();
        Predicate<ServerHttpRequest> isSecured = routeValidator.isSecured();
        assertTrue(isSecured.test(request));
    }

    @Test
    void testPartialMatchOpenEndpoint() {
        ServerHttpRequest request = MockServerHttpRequest.get("/auth/signup/123").build();
        Predicate<ServerHttpRequest> isSecured = routeValidator.isSecured();
        assertFalse(isSecured.test(request));
    }

}
