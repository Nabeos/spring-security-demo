package com.example.sessionspring.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.sessionspring.dto.CredentialsDto;
import com.example.sessionspring.entity.User;
import com.example.sessionspring.repo.UserRepository;
import com.example.sessionspring.security.UserAuthenticationProvider;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api")
public class UserController {
  @Autowired
  private UserRepository repo;
  @Autowired
  private PasswordEncoder passwordEncoder;
  @Autowired
  private UserAuthenticationProvider provider;

  @PostMapping("/login-session")
  public ResponseEntity<CredentialsDto> signInSession(@RequestBody CredentialsDto dto, HttpServletRequest request) {
    // authen
    Authentication auth = provider.validateCredentials(dto);
    SecurityContext securityContext = SecurityContextHolder.getContext();
    securityContext.setAuthentication(auth);

    // create new session and set session object
    HttpSession session = request.getSession(true);
    session.setAttribute(session.getId(), securityContext);
    return ResponseEntity.ok(dto);
  }

  @PostMapping("/register-session")
  public ResponseEntity<User> registerSession(@RequestBody User user) {
    User userNew = registerUser(user, "ROLE_USER");
    return ResponseEntity.ok(userNew);
  }

  @PostMapping("/register/admin")
  public ResponseEntity<User> registerAdminSession(@RequestBody User user) {
    User userNew = registerUser(user, "ROLE_ADMIN");
    return ResponseEntity.ok(userNew);
  }

  private User registerUser(User user, String role) {
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    user.setRole(role);
    repo.save(user);
    return user;
  }

  @GetMapping("/auth-session")
  public String getSessionUser() {
    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    String username = ((User) principal).getEmail();
    return username;
  }

  @GetMapping("/user")
  public String getUser() {
    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    return ((User) principal).getUsername();
  }

}
