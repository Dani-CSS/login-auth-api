package com.daniele.login_auth_api.controllers;

import com.daniele.login_auth_api.domain.user.User;
import com.daniele.login_auth_api.dto.LoginRequestDTO;
import com.daniele.login_auth_api.dto.RegisterRequestDTO;
import com.daniele.login_auth_api.dto.ResponseDTO;
import com.daniele.login_auth_api.infra.security.TokenService;
import com.daniele.login_auth_api.repositories.UserRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<ResponseDTO> login(@RequestBody LoginRequestDTO body) {
        User user = this.repository.findByEmail(body.email())
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (!passwordEncoder.matches(body.password(), user.getPassword())) {
            return ResponseEntity.badRequest().build();
        }

        String token = this.tokenService.generateToken(user);

        return ResponseEntity.ok(new ResponseDTO(user.getName(), token));
    }

    @PostMapping("/register")
    public ResponseEntity<ResponseDTO> register(@RequestBody RegisterRequestDTO body) {
        var userExists = this.repository.findByEmail(body.email());

        if (userExists.isPresent()) {
            return ResponseEntity.badRequest().build();
        }

        User newUser = new User();
        newUser.setName(body.name());
        newUser.setEmail(body.email());
        newUser.setPassword(passwordEncoder.encode(body.password()));

        this.repository.save(newUser);

        String token = this.tokenService.generateToken(newUser);

        return ResponseEntity.ok(new ResponseDTO(newUser.getName(), token));
    }
}
