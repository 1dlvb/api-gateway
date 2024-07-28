package com.fintech.apigateway.service.impl;

import com.fintech.apigateway.service.RouteValidator;
import org.springframework.http.server.reactive.ServerHttpRequest;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.function.Predicate;

/**
 * An implementation of {@link RouteValidator} interface.
 * @author Matushkin Anton
 */
@Service
public class RouteValidatorImpl implements RouteValidator {

    public static final List<String> OPEN_ENDPOINTS = List.of(
            "/auth/signin",
            "/auth/signup",
            "/auth/refresh-token"
    );

    @Override
    public Predicate<ServerHttpRequest> isSecured() {
        return servletServerHttpRequest -> OPEN_ENDPOINTS.stream()
                .noneMatch(uri -> servletServerHttpRequest.getURI().getPath().contains(uri));
    }

}
