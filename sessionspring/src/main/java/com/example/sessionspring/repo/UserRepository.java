package com.example.sessionspring.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.sessionspring.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

  User findByEmail(String login);

}
