package com.cravingapp.craving.controller;


import com.cravingapp.craving.model.User;
import com.cravingapp.craving.service.JwtService;
import com.cravingapp.craving.service.UserService;
import jakarta.persistence.Column;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public record LoginRequest(String username, String password) {}
    public record RegisterRequest(String username, String email, String password) {}
    public record UserDto(
            Long id,
            String username,
            String email,
            String bio,
            String profil_pic_url,
            LocalDateTime created_at
    ) {}
    public record AuthResponse(
            String token,
            UserDto userDto
    ) {}

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest) {
        User savedUser = new User();
        savedUser.setUsername(registerRequest.username);
        savedUser.setEmail(registerRequest.email);
        savedUser.setPassword(registerRequest.password);
        savedUser=userService.createUser(savedUser);
        UserDto userDto = new UserDto(
                (long)savedUser.getId(),
                savedUser.getUsername(),
                savedUser.getEmail(),
                savedUser.getBio(),
                savedUser.getProfile_picture_url(),
                savedUser.getCreated_at()
        );
        return new ResponseEntity<>(userDto, HttpStatus.CREATED);
    }
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        // 1. Spring verifies the password
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        // 2. Dacă e ok, luăm user-ul
        var user = (User) authentication.getPrincipal();

        // 3. Generăm un token
        String token = jwtService.generateToken(user);
        UserDto userDto = new UserDto((long) user.getId(),user.getUsername(),user.getEmail(),user.getBio(),user.getProfile_picture_url(),user.getCreated_at());

        // 4. Returnăm token-ul
        return ResponseEntity.ok(new AuthResponse(token,userDto));
    }
}
