package com.example.sessionspring.security;

import java.io.IOException;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

public class SessionAuthFilter extends OncePerRequestFilter {

  public SessionAuthFilter() {

  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    if ("/api/login-session".equals(request.getServletPath())) {
      filterChain.doFilter(request, response);
      return;
    }
    HttpSession session = request.getSession();
    SecurityContext context = (SecurityContext) session.getAttribute(session.getId());
    SecurityContextHolder.setContext(context);
    filterChain.doFilter(request, response);
  }

}
