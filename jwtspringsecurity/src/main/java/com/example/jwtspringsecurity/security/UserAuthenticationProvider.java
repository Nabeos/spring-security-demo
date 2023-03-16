package com.example.jwtspringsecurity.security;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwtspringsecurity.dto.CredentialsDto;
import com.example.jwtspringsecurity.entity.User;
import com.example.jwtspringsecurity.repo.UserRepository;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class UserAuthenticationProvider {
  private final UserRepository repository;
  private final PasswordEncoder passwordEncoder;
  private String secretKey = "NABEOS1001";

  public UserAuthenticationProvider(UserRepository repository, PasswordEncoder passwordEncoder) {
    this.repository = repository;
    this.passwordEncoder = passwordEncoder;
  }

  @PostConstruct
  protected void init() {
    secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
  }

  public Authentication validateCredentials(CredentialsDto credentialsDto) throws RuntimeException {
    User user = repository.findByEmail(credentialsDto.getLogin());
    List<SimpleGrantedAuthority> authorities = new ArrayList<>();
    authorities.add(new SimpleGrantedAuthority(user.getRoleName()));
    if (passwordEncoder.matches(credentialsDto.getPassword(), user.getPassword())) {
      UserDetails userDetails = new org.springframework.security.core.userdetails.User(user.getEmail(),
          user.getPassword(), true, true, true, true, authorities);
      UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
          userDetails, null, authorities);
      return usernamePasswordAuthenticationToken;
    }
    throw new RuntimeException("Invalid password");
  }

  public String createToken(String login) {
    Date now = new Date();
    Date validity = new Date(System.currentTimeMillis() + 3600000);
    return JWT.create()
        .withIssuer(login)
        .withIssuedAt(now)
        .withExpiresAt(validity)
        .sign(Algorithm.HMAC256(secretKey));
  }

  public String createRefreshToken(String login) {
    Date now = new Date();
    Date validity = new Date(now.getTime() + (60 * 60 * 24 * 30 * 1000));
    return JWT.create()
        .withIssuer(login)
        .withIssuedAt(now)
        .withExpiresAt(validity)
        .sign(Algorithm.HMAC256(secretKey));
  }

  public Authentication validateToken(String token, HttpServletRequest request) {
    Algorithm algorithm = Algorithm.HMAC256(secretKey);
    JWTVerifier verifier = JWT.require(algorithm).build();
    DecodedJWT decoded = verifier.verify(token);
    User user = repository.findByEmail(decoded.getIssuer());
    List<SimpleGrantedAuthority> authorities = new ArrayList<>();
    authorities.add(new SimpleGrantedAuthority(user.getRoleName()));

    UserDetails userDetails = new org.springframework.security.core.userdetails.User(user.getEmail(),
        user.getPassword(), true, true, true, true, authorities);
    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
        userDetails, null, authorities);
    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    return usernamePasswordAuthenticationToken;
  }

  public String validateRefreshToken(String refreshToken, HttpServletRequest request) {
    User user = repository.findByRefreshToken(refreshToken).orElseThrow(() -> new RuntimeException("Not found"));
    return user.getEmail();
  }
}
