package com.example.sessionspring.dto;

public class UserDTO {
  private String name;
  private String role;

  public UserDTO(String name, String role) {
    this.name = name;
    this.role = role;
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

}
