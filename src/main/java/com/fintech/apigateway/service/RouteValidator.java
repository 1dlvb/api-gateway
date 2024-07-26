package com.fintech.apigateway.service;

import org.springframework.http.server.reactive.ServerHttpRequest;
import java.util.function.Predicate;

public interface RouteValidator {

    Predicate<ServerHttpRequest> isSecured();

}
