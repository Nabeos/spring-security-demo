package com.example.sessionspring.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SessionConfiguration {
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/login-session", "/api/register", "/api/register-session", "/api/register/admin")
            .permitAll()
            .requestMatchers(HttpMethod.GET, "/api/auth-session/**")
            .hasAnyAuthority("ROLE_ADMIN")
            .requestMatchers(HttpMethod.GET, "/api/user/**")
            .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
            .anyRequest().authenticated())
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
        .logout(logout -> logout.deleteCookies("JSESSIONID")
            .invalidateHttpSession(true))
        .addFilterAfter(new SessionAuthFilter(), UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }
}
