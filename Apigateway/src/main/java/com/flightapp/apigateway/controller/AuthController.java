package com.flightapp.apigateway.controller;

import com.flightapp.apigateway.model.User;
import com.flightapp.apigateway.repository.UserRepository;
import com.flightapp.apigateway.security.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import com.flightapp.apigateway.DTO.PasswordChange;

import java.time.LocalDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials = "true")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @PostMapping("/change")
    public Mono<ResponseEntity<Object>> changePassword(@RequestBody PasswordChange request) {
        return userRepository.findByUsername(request.getUsername())
                .flatMap(user -> {
                    user.setPassword(encoder.encode(request.getNewPassword()));
                    user.setLastPasswordUpdatedAt(LocalDateTime.now());
                    return userRepository.save(user)
                            .map(saved -> ResponseEntity.ok((Object) Map.of("message", "Password updated successfully")));
                })
                .switchIfEmpty(Mono.just(ResponseEntity.status(404).body((Object) Map.of("message", "User not found"))));
    }

    @PostMapping("/signup")
    public Mono<ResponseEntity<?>> register(@RequestBody User user) {
        return userRepository.existsByUsername(user.getUsername())
                .flatMap(exists -> {
                    if (exists) {
                        Map<String, String> errorResponse = new HashMap<>();
                        errorResponse.put("message", "Username already exists");
                        return Mono.just(ResponseEntity.badRequest().body(errorResponse));
                    }

                    return userRepository.existsByEmail(user.getEmail())
                            .flatMap(emailExists -> {
                                if (emailExists) {
                                    Map<String, String> errorResponse = new HashMap<>();
                                    errorResponse.put("message", "Email already in use");
                                    return Mono.just(ResponseEntity.badRequest().body(errorResponse));
                                }

                                user.setPassword(encoder.encode(user.getPassword()));
                                user.setRoles(Set.of("ROLE_USER"));
                                user.setLastPasswordUpdatedAt(LocalDateTime.now());

                                return userRepository.save(user)
                                        .map(saved -> {
                                            Map<String, String> successResponse = new HashMap<>();
                                            successResponse.put("message", "User registered successfully!");
                                            return ResponseEntity.ok().body(successResponse);
                                        });
                            });
                });
    }

    @PostMapping("/signin")
    public Mono<ResponseEntity<?>> login(@RequestBody User user) {
        return userRepository.findByUsername(user.getUsername())
                .flatMap(dbUser -> {
                    if (!encoder.matches(user.getPassword(), dbUser.getPassword())) {
                        Map<String, String> errorResponse = new HashMap<>();
                        errorResponse.put("message", "Invalid credentials");
                        return Mono.just((ResponseEntity<?>) ResponseEntity.status(401).body(errorResponse));
                    }

                    String token = jwtUtils.generateJwt(dbUser.getUsername());

                    // this is the HttpOnly Cookie creation i am doing
                    ResponseCookie cookie = ResponseCookie.from("bezkoder", token)
                            .httpOnly(true)
                            .secure(false)  // Set to true in production with HTTPS
                            .path("/")
                            .maxAge(24 * 60 * 60)
                            .sameSite("Lax")
                            .build();

                    Map<String, Object> response = new HashMap<>();
                    response.put("id", dbUser.getId());
                    response.put("username", dbUser.getUsername());
                    response.put("email", dbUser.getEmail());
                    response.put("roles", new ArrayList<>(dbUser.getRoles()));
                    response.put("lastPasswordUpdatedAt", dbUser.getLastPasswordUpdatedAt());

                    return Mono.just(
                            (ResponseEntity<?>) ResponseEntity.ok()
                                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                                    .body(response)
                    );
                })
                .switchIfEmpty(Mono.fromSupplier(() -> {
                    Map<String, String> errorResponse = new HashMap<>();
                    errorResponse.put("message", "User not found");
                    return (ResponseEntity<?>) ResponseEntity.status(401).body(errorResponse);
                }));
    }

    @PostMapping("/signout")
    public Mono<ResponseEntity<?>> logout() {
        ResponseCookie cookie = ResponseCookie.from("bezkoder", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .build();

        Map<String, String> response = new HashMap<>();
        response.put("message", "You've been signed out!");

        return Mono.just(
                ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, cookie.toString())
                        .body(response)
        );
    }
}