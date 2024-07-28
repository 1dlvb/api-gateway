package com.fintech.apigateway.config;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.netflix.hystrix.EnableHystrix;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class for defining routes in the API Gateway.
 * @author Matushkin Anton
 */
@Configuration
@EnableHystrix
@RequiredArgsConstructor
public class GatewayConfig {

    @Value("${service.uri.deal}")
    private String dealServiceUri;

    @Value("${service.uri.contractor}")
    private String contractorServiceUri;

    @Value("${service.uri.auth}")
    private String authServiceUri;

    @NonNull
    private AuthenticationFilter authenticationFilter;

    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder) {
        RouteLocatorBuilder.Builder routesBuilder = builder.routes();

        addAuthRoutes(routesBuilder);
        addUserRoleRoutes(routesBuilder);
        addCreditOrOverdraftUserRoleRoutes(routesBuilder);
        addDealSuperuserRoleRoutes(routesBuilder);
        addContractorRusRoleRoutes(routesBuilder);
        addContractorSuperuserRoutes(routesBuilder);
        addAdminRoutes(routesBuilder);

        return routesBuilder.build();
    }

    /**
     * Adds authentication routes to the provided routes builder.
     * @param routes the routes builder
     */
    private void addAuthRoutes(RouteLocatorBuilder.Builder routes) {
        routes.route(r -> r.path("/auth/signin").uri(authServiceUri))
                .route(r -> r.path("/auth/signup").uri(authServiceUri))
                .route(r -> r.path("/auth/refresh-token").uri(authServiceUri));
    }

    /**
     * Adds user role routes to the provided routes builder.
     * @param routes the routes builder
     */
    private void addUserRoleRoutes(RouteLocatorBuilder.Builder routes) {
        routes.route(r -> r.path("/deal/**")
                    .and()
                    .method("GET")
                    .filters(f -> f.filter(authenticationFilter))
                    .uri(dealServiceUri))
                .route(r -> r.path("/contractor/**")
                    .and()
                    .method("GET")
                    .filters(f -> f.filter(authenticationFilter))
                    .uri(contractorServiceUri))
                .route(r -> r.path("/user-roles/**")
                    .and()
                    .method("GET")
                    .filters(f -> f.filter(authenticationFilter))
                    .uri(authServiceUri));

    }

    /**
     * Adds credit or overdraft user role routes to the provided routes builder.
     * @param routes the routes builder
     */
    private void addCreditOrOverdraftUserRoleRoutes(RouteLocatorBuilder.Builder routes) {
        routes.route(r -> r.path("/deal/search")
                    .and()
                    .method("POST")
                    .filters(f -> f.filter(authenticationFilter))
                    .uri(dealServiceUri));

    }

    /**
     * Adds deal superuser role routes to the provided routes builder.
     * @param routes the routes builder
     */
    private void addDealSuperuserRoleRoutes(RouteLocatorBuilder.Builder routes) {
        routes.route(r -> r.path("/deal/**")
                    .filters(f -> f.filter(authenticationFilter))
                    .uri(dealServiceUri))
                .route(r -> r.path("/deal-contractor/**")
                    .filters(f -> f.filter(authenticationFilter))
                    .uri(dealServiceUri))
                .route(r -> r.path("/contractor-to-role/**")
                    .filters(f -> f.filter(authenticationFilter))
                    .uri(dealServiceUri));

    }

    /**
     * Adds contractor RUS role routes to the provided routes builder.
     * @param routes the routes builder
     */
    private void addContractorRusRoleRoutes(RouteLocatorBuilder.Builder routes) {
        routes.route(r -> r.path("/contractor/search")
                .and()
                .method("POST")
                .filters(f -> f.filter(authenticationFilter))
                .uri(contractorServiceUri));
    }

    /**
     * Adds contractor superuser routes to the provided routes builder.
     * @param routes the routes builder
     */
    private void addContractorSuperuserRoutes(RouteLocatorBuilder.Builder routes) {
        routes.route(r -> r.path("/contractor/**")
                .filters(f -> f.filter(authenticationFilter))
                .uri(contractorServiceUri));
    }

    /**
     * Adds admin routes to the provided routes builder.
     * @param routes the routes builder
     */
    private void addAdminRoutes(RouteLocatorBuilder.Builder routes) {
        routes.route(r -> r.path("/auth/**")
                        .filters(f -> f.filter(authenticationFilter))
                        .uri(authServiceUri))
                .route(r -> r.path("/roles/**")
                        .filters(f -> f.filter(authenticationFilter))
                        .uri(authServiceUri));
    }

}
