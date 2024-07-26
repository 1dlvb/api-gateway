package com.fintech.apigateway.config;

import com.fintech.apigateway.service.RouteValidator;
import com.fintech.apigateway.util.JWTUtil;
import com.fintech.apigateway.util.Roles;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
@RequiredArgsConstructor
public class AuthenticationFilter implements GatewayFilter {

    @NonNull
    private RouteValidator validator;
    @NonNull
    private JWTUtil jwtUtil;
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        if (validator.isSecured().test(request)) {
            if (authMissing(request)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            final String token = request.getHeaders().getOrEmpty("Authorization").get(0);


            if (jwtUtil.isTokenExpired(token) || jwtUtil.getRoleFromToken(token) == null) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }
            Roles role = Roles.valueOf(jwtUtil.getRoleFromToken(token));
            if (!isAllowedRoleForPath(role, request.getURI(), request.getURI().getPath(), request.getMethod().name())) {
                return onError(exchange, HttpStatus.FORBIDDEN);
            }
        }
        return chain.filter(exchange);
    }

    private boolean isAllowedRoleForPath(Roles role, URI pathURI, String path, String method) {
        return switch (role) {
            case USER -> isUserAllowed(path, method);
            case CREDIT_USER -> isCreditUserAllowed(path, pathURI, method);
            case OVERDRAFT_USER -> isOverdraftUserAllowed(path, pathURI, method);
            case DEAL_SUPERUSER -> isDealSuperUserAllowed(path);
            case CONTRACTOR_RUS -> isContractorRusAllowed(path, pathURI, method);
            case CONTRACTOR_SUPERUSER -> isContractorSuperuserAllowed(path, method);
            case SUPERUSER -> isSuperuserAllowed(path, method);
            case ADMIN -> isAdminAllowed(path);
        };
    }

    private boolean isUserAllowed(String path, String method) {
        return method.equals("GET") && (path.matches("^/contractor/.*") ||
                path.matches("^/deal/.*"));
    }

    private boolean isCreditUserAllowed(String path, URI pathURI, String method) {
        return isUserAllowed(path, method) ||
                (method.equals("POST") && path.matches("/deal/search") && isDealType(pathURI, "CREDIT"));
    }

    private boolean isOverdraftUserAllowed(String path, URI pathURI, String method) {
        return isUserAllowed(path, method) ||
                (method.equals("POST") && path.matches("/deal/search") && isDealType(pathURI, "OVERDRAFT"));
    }

    private boolean isDealSuperUserAllowed(String path) {
        return path.matches("^/deal/.*") ||
                path.matches("^/contractor-to-role/.*") ||
                path.matches("^/deal-contractor/.*");
    }

    private boolean isContractorRusAllowed(String path, URI pathURI, String method) {
        return isUserAllowed(path, method) ||
                (method.equals("POST") && path.matches("/contractor/search") && isCountry(pathURI, "RUS"));
    }

    private boolean isContractorSuperuserAllowed(String path, String method) {
        return isUserAllowed(path, method) ||
                 path.matches("^/contractor/.*");
    }

    private boolean isSuperuserAllowed(String path, String method) {
        return isDealSuperUserAllowed(path) || isContractorSuperuserAllowed(path, method);
    }

    private boolean isAdminAllowed(String path) {
        return path.matches("^/auth/.*");
    }

    private boolean isDealType(URI path, String dealType) {
        return path.toString().contains(String.format("type=%s", dealType));
    }

    private boolean isCountry(URI path, String country) {
        return path.toString().contains(String.format("country=%s", country));
    }

    private boolean authMissing(ServerHttpRequest request) {
        return !request.getHeaders().containsKey("Authorization");
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

}
