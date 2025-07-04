package com.bookstore.userservice;

import com.bookstore.userservice.dto.LoginRequest;
import com.bookstore.userservice.model.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final JwtTokenProvider jwtProvider;
    private final AuthenticationManager authManager;

    public UserController(UserService us, JwtTokenProvider jp, AuthenticationManager am) {
        this.userService = us;
        this.jwtProvider = jp;
        this.authManager = am;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        if (userService.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username already exists");
        }
        return ResponseEntity.ok(userService.register(user));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        authManager.authenticate(
            new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword()));
        String token = jwtProvider.createToken(req.getUsername());
        return ResponseEntity.ok(Map.of("token", token));
    }
}
