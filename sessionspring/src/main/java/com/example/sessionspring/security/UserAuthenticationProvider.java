package com.example.sessionspring.security;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.example.sessionspring.dto.CredentialsDto;
import com.example.sessionspring.entity.User;
import com.example.sessionspring.repo.UserRepository;

import jakarta.annotation.PostConstruct;

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
    authorities.add(new SimpleGrantedAuthority(user.getRole()));
    if (passwordEncoder.matches(credentialsDto.getPassword(), user.getPassword())) {
      return new UsernamePasswordAuthenticationToken(user, null, authorities);
    }
    throw new RuntimeException("Invalid password");
  }

}
