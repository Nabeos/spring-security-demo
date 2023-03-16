package com.example.sessionspring.security;

import java.io.IOException;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.sessionspring.dto.CredentialsDto;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class UsernamePasswordAuthFilter extends OncePerRequestFilter {

  private static final ObjectMapper mapper = new ObjectMapper();

  private UserAuthenticationProvider provider;

  public UsernamePasswordAuthFilter(UserAuthenticationProvider provider) {
    this.provider = provider;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    if ("/api/login".equals(request.getServletPath()) && HttpMethod.POST.matches(request.getMethod())) {
      // read credentials from the login request
      CredentialsDto credentialsDto = mapper.readValue(request.getInputStream(), CredentialsDto.class);
      System.out.println("vao user password auth");
      try {
        SecurityContextHolder.getContext().setAuthentication(provider.validateCredentials(credentialsDto));
      } catch (RuntimeException e) {
        SecurityContextHolder.clearContext();
        throw e;
      }
    }
    filterChain.doFilter(request, response);
  }

}
