package com.dilshan.keycloak.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
@Slf4j
public class DemoController {

    @GetMapping
    @PreAuthorize("hasRole('client_user')")
    public String hello() {
        return "Hello from Spring boot keycloak!";
    }

    @GetMapping("/hello")
    @PreAuthorize("hasRole('client_admin')")
    public String hello_2(JwtAuthenticationToken jwt) {
        log.info("JWT Token: {}", jwt.getToken().getClaims().toString());
        return "Hello from Spring boot keycloak Hello Admin!";
    }

    @GetMapping("/test")
    public String test() {
        log.info("Test method called!");
        return "Hello test method";
    }

}
