package com.example.jwtspringsecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
  private final UserAuthenticationProvider userAuthenticationProvider;
  private final UserAuthenticationEntryPoint userAuthenticationEntryPoint;

  public WebSecurityConfig(UserAuthenticationProvider userAuthenticationProvider,
      UserAuthenticationEntryPoint userAuthenticationEntryPoint) {
    this.userAuthenticationProvider = userAuthenticationProvider;
    this.userAuthenticationEntryPoint = userAuthenticationEntryPoint;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    http.csrf().disable()
        .exceptionHandling().authenticationEntryPoint(userAuthenticationEntryPoint).and()
        .authorizeHttpRequests()
        .requestMatchers("/api/login", "/api/register", "/api/register/admin", "/api/refresh-token").permitAll()
        .requestMatchers(HttpMethod.GET,"/api/auth/**").hasAnyAuthority("ROLE_ADMIN")
        .requestMatchers(HttpMethod.GET, "/api/user/**").hasAnyAuthority("ROLE_USER")
        .anyRequest().authenticated().and()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    http.addFilterBefore(new UsernamePasswordAuthFilter(userAuthenticationProvider), BasicAuthenticationFilter.class);
    http.addFilterBefore(new JwtAuthFilter(userAuthenticationProvider), UsernamePasswordAuthFilter.class);
    return http.build();
  }
}
