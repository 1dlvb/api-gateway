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
import java.util.List;

/**
 * A filter that authenticates requests using JWT tokens.
 * @author Matushkin Anton
 */
@Component
@RequiredArgsConstructor
public class AuthenticationFilter implements GatewayFilter {

    @NonNull
    private RouteValidator validator;
    @NonNull
    private JWTUtil jwtUtil;

    /**
     * Filters incoming requests and applies authentication checks.
     * @param exchange the current server exchange
     * @param chain the gateway filter chain
     * @return a {@link Mono} indicating when request handling is complete
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        if (validator.isSecured().test(request)) {
            if (authMissing(request)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            final String token = request.getHeaders().getOrEmpty("Authorization").get(0);

            if (jwtUtil.isTokenExpired(token)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }
            if (jwtUtil.getRolesFromToken(token) == null) {
                return onError(exchange, HttpStatus.INTERNAL_SERVER_ERROR);
            }

            boolean isAllowed = isAllowed(token, request);
            if (!isAllowed) {
                return onError(exchange, HttpStatus.FORBIDDEN);
            }
        }
        return chain.filter(exchange);
    }

    /**
     * Checks if the token allows the user to access the requested resource.
     * @param token the JWT token
     * @param request the current server request
     * @return true if the user is allowed to access the resource, false otherwise
     */
    private boolean isAllowed(String token, ServerHttpRequest request) {
        List<String> roles = jwtUtil.getRolesFromToken(token);
        boolean isAllowed = false;
        for (String role : roles) {
            if (isAllowedRoleForPath(Roles.valueOf(role),
                    request.getURI(),
                    request.getURI().getPath(),
                    request.getMethod().name(),
                    token)) {
                isAllowed = true;
                break;
            }
        }
        return isAllowed;
    }

    /**
     * Determines if the specified role is allowed to access the requested path and method.
     * @param role the role of the user
     * @param pathURI the URI of the requested resource
     * @param path the path of the requested resource
     * @param method the HTTP method of the request
     * @param token the JWT token
     * @return true if the role is allowed to access the resource, false otherwise
     */
    private boolean isAllowedRoleForPath(Roles role, URI pathURI, String path, String method, String token) {
        return switch (role) {
            case USER -> isUserAllowed(path, method, token);
            case CREDIT_USER -> isCreditUserAllowed(path, pathURI, method, token);
            case OVERDRAFT_USER -> isOverdraftUserAllowed(path, pathURI, method, token);
            case DEAL_SUPERUSER -> isDealSuperUserAllowed(path);
            case CONTRACTOR_RUS -> isContractorRusAllowed(path, pathURI, method, token);
            case CONTRACTOR_SUPERUSER -> isContractorSuperuserAllowed(path, method, token);
            case SUPERUSER -> isSuperuserAllowed(path, method, token);
            case ADMIN -> isAdminAllowed(path);
        };
    }

    /**
     * Checks if a USER role is allowed to access the requested path and method.
     * @param path the path of the requested resource
     * @param method the HTTP method of the request
     * @param token the JWT token
     * @return true if the USER role is allowed, false otherwise
     */
    private boolean isUserAllowed(String path, String method, String token) {
        String username = jwtUtil.getUsernameFromToken(token);
        return method.equals("GET") && (path.matches("^/contractor/.*") ||
                path.matches("^/deal/.*") || path.matches(String.format("^/user-roles/%s", username)));
    }

    /**
     * Checks if a CREDIT_USER role is allowed to access the requested path and method.
     * @param path the path of the requested resource
     * @param pathURI the URI of the requested resource
     * @param method the HTTP method of the request
     * @param token the JWT token
     * @return true if the CREDIT_USER role is allowed, false otherwise
     */
    private boolean isCreditUserAllowed(String path, URI pathURI, String method, String token) {
        return isUserAllowed(path, method, token) ||
                (method.equals("POST") && path.matches("/deal/search") && isDealType(pathURI, "CREDIT"));
    }

    /**
     * Checks if an OVERDRAFT_USER role is allowed to access the requested path and method.
     * @param path the path of the requested resource
     * @param pathURI the URI of the requested resource
     * @param method the HTTP method of the request
     * @param token the JWT token
     * @return true if the OVERDRAFT_USER role is allowed, false otherwise
     */
    private boolean isOverdraftUserAllowed(String path, URI pathURI, String method, String token) {
        return isUserAllowed(path, method, token) ||
                (method.equals("POST") && path.matches("/deal/search") && isDealType(pathURI, "OVERDRAFT"));
    }

    /**
     * Checks if a DEAL_SUPERUSER role is allowed to access the requested path.
     * @param path the path of the requested resource
     * @return true if the DEAL_SUPERUSER role is allowed, false otherwise
     */
    private boolean isDealSuperUserAllowed(String path) {
        return path.matches("^/deal/.*") ||
                path.matches("^/contractor-to-role/.*") ||
                path.matches("^/deal-contractor/.*");
    }

    /**
     * Checks if a CONTRACTOR_RUS role is allowed to access the requested path and method.
     * @param path the path of the requested resource
     * @param pathURI the URI of the requested resource
     * @param method the HTTP method of the request
     * @param token the JWT token
     * @return true if the CONTRACTOR_RUS role is allowed, false otherwise
     */
    private boolean isContractorRusAllowed(String path, URI pathURI, String method, String token) {
        return isUserAllowed(path, method, token) ||
                (method.equals("POST") && path.matches("/contractor/search") && isCountry(pathURI, "RUS"));
    }

    /**
     * Checks if a CONTRACTOR_SUPERUSER role is allowed to access the requested path and method.
     * @param path the path of the requested resource
     * @param method the HTTP method of the request
     * @param token the JWT token
     * @return true if the CONTRACTOR_SUPERUSER role is allowed, false otherwise
     */
    private boolean isContractorSuperuserAllowed(String path, String method, String token) {
        return isUserAllowed(path, method, token) ||
                 path.matches("^/contractor/.*");
    }

    /**
     * Checks if a SUPERUSER role is allowed to access the requested path and method.
     * @param path the path of the requested resource
     * @param method the HTTP method of the request
     * @param token the JWT token
     * @return true if the SUPERUSER role is allowed, false otherwise
     */
    private boolean isSuperuserAllowed(String path, String method, String token) {
        return isDealSuperUserAllowed(path) || isContractorSuperuserAllowed(path, method, token);
    }

    /**
     * Checks if an ADMIN role is allowed to access the requested path.
     * @param path the path of the requested resource
     * @return true if the ADMIN role is allowed, false otherwise
     */
    private boolean isAdminAllowed(String path) {
        return path.matches("^/auth/.*") ||
                path.matches("^/roles/.*") ||
                path.matches("^/user-roles/.*");
    }

    /**
     * Checks if the deal type in the URI matches the specified deal type.
     * @param path the URI of the requested resource
     * @param dealType the deal type to check for
     * @return true if the deal type matches, false otherwise
     */
    private boolean isDealType(URI path, String dealType) {
        return path.toString().contains(String.format("type=%s", dealType));
    }

    /**
     * Checks if the country in the URI matches the specified country.
     * @param path the URI of the requested resource
     * @param country the country to check for
     * @return true if the country matches, false otherwise
     */
    private boolean isCountry(URI path, String country) {
        return path.toString().contains(String.format("country=%s", country));
    }

    /**
     * Checks if the request is missing the Authorization header.
     * @param request the current server request
     * @return true if the Authorization header is missing, false otherwise
     */
    private boolean authMissing(ServerHttpRequest request) {
        return !request.getHeaders().containsKey("Authorization");
    }

    /**
     * Responds with the specified HTTP status code and completes the request.
     * @param exchange the current server exchange
     * @param httpStatus the HTTP status code to respond with
     * @return a {@link Mono} indicating when the response is complete
     */
    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

}
