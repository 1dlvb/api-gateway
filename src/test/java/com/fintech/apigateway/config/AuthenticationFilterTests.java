package com.fintech.apigateway.config;

import com.fintech.apigateway.service.RouteValidator;
import com.fintech.apigateway.util.JWTUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationFilterTests {

    @Mock(lenient = true)
    private RouteValidator validator;

    @Mock(lenient = true)
    private JWTUtil jwtUtil;

    @Mock(lenient = true)
    private GatewayFilterChain chain;

    @Mock(lenient = true)
    private ServerWebExchange exchange;

    @InjectMocks
    private AuthenticationFilter authenticationFilter;

    @BeforeEach
    void setUp() {
        ServerHttpRequest mockRequest = MockServerHttpRequest.get("/contractor/country/all")
                .header(HttpHeaders.AUTHORIZATION, "Bearer validToken")
                .build();

        when(exchange.getRequest()).thenReturn(mockRequest);
        when(exchange.getResponse()).thenReturn(new MockServerHttpResponse());
        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());
    }

    @Test
    void testFilterWithOpenEndpointShouldNotFilter() {
        when(validator.isSecured()).thenReturn(request -> false);

        Mono<Void> result = authenticationFilter.filter(exchange, chain);

        verify(chain, times(1)).filter(exchange);
        assertTrue(result.blockOptional().isEmpty());
    }

    @Test
    void testFilterWithMissingAuthorizationHeaderReturnUnauthorized() {
        ServerHttpRequest requestWithoutAuth = MockServerHttpRequest.get("/secured/endpoint").build();
        when(exchange.getRequest()).thenReturn(requestWithoutAuth);
        when(validator.isSecured()).thenReturn(request -> true);

        Mono<Void> result = authenticationFilter.filter(exchange, chain);

        ServerHttpResponse response = exchange.getResponse();
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertTrue(result.blockOptional().isEmpty());
    }

    @Test
    void testFilterWithExpiredTokenReturnUnauthorized() {
        when(validator.isSecured()).thenReturn(request -> true);
        when(jwtUtil.isTokenExpired(anyString())).thenReturn(true);

        Mono<Void> result = authenticationFilter.filter(exchange, chain);

        ServerHttpResponse response = exchange.getResponse();
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertTrue(result.blockOptional().isEmpty());
    }

    @Test
    void testFilterWithValidTokenAndRolesAllowAccess() {
        when(validator.isSecured()).thenReturn(request -> true);
        when(jwtUtil.isTokenExpired(anyString())).thenReturn(false);
        when(jwtUtil.getRolesFromToken(anyString())).thenReturn(List.of("USER"));

        Mono<Void> result = authenticationFilter.filter(exchange, chain);

        verify(chain, times(1)).filter(exchange);
        assertTrue(result.blockOptional().isEmpty());
    }

    @Test
    void testFilterWithValidTokenAndNotAllowedRoleNotAllowAccess() {
        when(validator.isSecured()).thenReturn(request -> true);
        when(jwtUtil.isTokenExpired(anyString())).thenReturn(false);
        when(jwtUtil.getRolesFromToken(anyString())).thenReturn(List.of("ADMIN"));

        Mono<Void> result = authenticationFilter.filter(exchange, chain);
        ServerHttpResponse response = exchange.getResponse();

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertTrue(result.blockOptional().isEmpty());
    }


}
