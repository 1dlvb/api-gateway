package com.fintech.apigateway.service;

import org.springframework.http.server.reactive.ServerHttpRequest;
import java.util.function.Predicate;

/**
 * Interface for validating routes.
 * Determines whether a route requires security checks.
 * @author Matushkin Anton
 */
public interface RouteValidator {

    Predicate<ServerHttpRequest> isSecured();

}
