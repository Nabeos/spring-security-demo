package com.example.jwtspringsecurity.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.jwtspringsecurity.dto.UserDTO;
import com.example.jwtspringsecurity.entity.User;
import com.example.jwtspringsecurity.repo.UserRepository;
import com.example.jwtspringsecurity.security.UserAuthenticationProvider;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api")
public class UserController {
  @Autowired
  private UserRepository repo;
  @Autowired
  private PasswordEncoder passwordEncoder;
  @Autowired
  private UserAuthenticationProvider provider;

  @PostMapping("/login")
  public UserDTO signIn(@AuthenticationPrincipal UserDetails user, HttpServletResponse response) {
    String token = provider.createToken(user.getUsername());
    User currentUser = repo.findByEmail(user.getUsername());

    String refreshToken = currentUser.getRefreshToken();
    Cookie cookie = new Cookie("refresh_tok", refreshToken);
    cookie.setHttpOnly(true);
    cookie.setMaxAge(60 * 60 * 24 * 30);
    response.addCookie(cookie);

    return new UserDTO(user.getUsername(), user.getAuthorities().toString(), token, refreshToken);
  }

  @PostMapping("/register")
  public UserDTO register(@RequestBody User user, HttpServletResponse response) {
    // set pass and role
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    user.setRoleName("ROLE_USER");

    // create token
    String token = provider.createToken(user.getEmail());

    // create refresh token
    String refreshToken = provider.createRefreshToken(user.getEmail());
    Cookie cookie = new Cookie("refresh_tok", refreshToken);
    cookie.setHttpOnly(true);
    cookie.setMaxAge(60 * 60 * 24 * 30);
    response.addCookie(cookie); // add refresh token in cookie
    user.setRefreshToken(refreshToken); // add refresh token in db
    repo.save(user);
    return new UserDTO(user.getEmail(), user.getRoleName(), token, refreshToken);
  }

  @PostMapping("/register/admin")
  public Map<String, String> registerAdmin(@RequestBody User user, HttpServletResponse response) {
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    user.setRoleName("ROLE_ADMIN");

    String token = provider.createToken(user.getEmail());
    String refreshToken = provider.createRefreshToken(user.getEmail());
    user.setRefreshToken(refreshToken);
    repo.save(user);
    Cookie cookie = new Cookie("refresh_tok", refreshToken);
    cookie.setHttpOnly(true);
    cookie.setMaxAge(60 * 60 * 24 * 30);
    response.addCookie(cookie);

    Map<String, String> tokens = new HashMap<>();
    tokens.put("access_token", token);
    tokens.put("refresh_token", refreshToken);
    return tokens;
  }

  @GetMapping("/auth")
  public String getAdmin() {
    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    return ((UserDetails) principal).getUsername();
  }

  @GetMapping("/user")
  public String getUser() {
    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    return ((UserDetails) principal).getUsername();
  }

  @GetMapping("/refresh-token")
  public String refreshToken(HttpServletRequest request, HttpServletResponse response) {
    Cookie[] cookies = request.getCookies();
    String refreshToken = null;

    for (Cookie cookie : cookies) {
      if (cookie.getName().equals("refresh_tok")) {
        refreshToken = cookie.getValue();
      }
    }
    String email = provider.validateRefreshToken(refreshToken, request);
    String token = provider.createToken(email);
    return "ACCESS_TOKEN: "+token;
  }

}
