package com.example.jwtspringsecurity.security;

import java.io.IOException;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtWithCookieAuthFilter extends OncePerRequestFilter {
  private UserAuthenticationProvider provider;

  public JwtWithCookieAuthFilter(UserAuthenticationProvider provider) {
    this.provider = provider;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    if ("/api/refresh-token".equals(request.getServletPath())) {
      filterChain.doFilter(request, response);
    }
    String token = null;

    // cookie carries jwt
    Cookie[] cookies = request.getCookies();
    for (Cookie cookie : cookies) {
      if ("jwt_auth".equals(cookie.getName())) {
        token = cookie.getValue();
      }
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
