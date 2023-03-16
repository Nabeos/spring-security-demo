package com.example.jwtspringsecurity.security;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthFilter extends OncePerRequestFilter {
  private UserAuthenticationProvider provider;

  public JwtAuthFilter(UserAuthenticationProvider provider) {
    this.provider = provider;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    if ("/api/refresh-token".equals(request.getServletPath())) {
      filterChain.doFilter(request, response);
    }

    String header = request.getHeader(HttpHeaders.AUTHORIZATION);
    String token = null;
    if (header != null && header.startsWith("Bearer ")) {
      token = header.substring(8, header.length());
    }

    if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      try {
        System.out.println(token);
        SecurityContextHolder.getContext().setAuthentication(provider.validateToken(token, request));
      } catch (RuntimeException e) {
        SecurityContextHolder.clearContext();
        throw e;
      }
    }

    filterChain.doFilter(request, response);

  }

}
