package com.example.jwtspringsecurity.dto;

public class UserDTO {
  private String name;
  private String role;
  private String token;
  private String refreshToken;

  public UserDTO(String name, String role, String token, String refreshToken) {
    this.name = name;
    this.role = role;
    this.token = token;
    this.refreshToken = refreshToken;
  }

  public String getRefreshToken() {
    return this.refreshToken;
  }

  public void setRefreshToken(String refreshToken) {
    this.refreshToken = refreshToken;
  }

  public UserDTO() {
  }

  public String getName() {
    return this.name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getRole() {
    return this.role;
  }

  public void setRole(String role) {
    this.role = role;
  }

  public String getToken() {
    return this.token;
  }

  public void setToken(String token) {
    this.token = token;
  }

}
