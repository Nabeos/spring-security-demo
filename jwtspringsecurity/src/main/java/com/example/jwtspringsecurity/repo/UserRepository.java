package com.example.jwtspringsecurity.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.jwtspringsecurity.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

  User findByEmail(String login);

  Optional<User> findByRefreshToken(String token);

}
