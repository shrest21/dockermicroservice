package com.flightapp.apigateway.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/test")
@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials = "true")
public class TestController {

    @GetMapping("/all")
    public Mono<ResponseEntity<String>> allAccess() {
        return Mono.just(ResponseEntity.ok("Public Content."));
    }

    @GetMapping("/user")
    public Mono<ResponseEntity<String>> userAccess() {
        return Mono.just(ResponseEntity.ok("User Content."));
    }

    @GetMapping("/mod")
    public Mono<ResponseEntity<String>> moderatorAccess() {
        return Mono.just(ResponseEntity.ok("Moderator Board."));
    }

    @GetMapping("/admin")
    public Mono<ResponseEntity<String>> adminAccess() {
        return Mono.just(ResponseEntity.ok("Admin Board."));
    }
}