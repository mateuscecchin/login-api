package com.app.login.controller;

import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.app.login.domain.user.User;
import com.app.login.dto.LoginRequestDTO;
import com.app.login.dto.LoginResponseDTO;
import com.app.login.dto.RegisterRequestDTO;
import com.app.login.dto.RegisterResponseDTO;
import com.app.login.infra.security.TokenService;
import com.app.login.repositories.UserRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
	private final UserRepository repository;
	private final PasswordEncoder passwordEncoder;
	private final TokenService tokenService;

	@PostMapping("/login")
	public ResponseEntity login(@RequestBody LoginRequestDTO body) {
		User user = this.repository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User not found"));
		if(passwordEncoder.matches(body.password(), user.getPassword())) {
			String token = this.tokenService.generateToken(user);

			return ResponseEntity.ok(new LoginResponseDTO(user.getName(), token));
		}	

		return ResponseEntity.badRequest().build();
	}

	@PostMapping("/register")
	public ResponseEntity register(@RequestBody RegisterRequestDTO body) {
		Optional<User> user = this.repository.findByEmail(body.email());

		if(!user.isEmpty()) return ResponseEntity.badRequest().build();

		User newUser = new User();

		String password = this.passwordEncoder.encode(body.password());

		newUser.setEmail(body.email());
		newUser.setName(body.name());
		newUser.setPassword(password);

		this.repository.save(newUser);

		String token = this.tokenService.generateToken(newUser);

		return ResponseEntity.ok(new RegisterResponseDTO(newUser.getName(), token));
	}
}
