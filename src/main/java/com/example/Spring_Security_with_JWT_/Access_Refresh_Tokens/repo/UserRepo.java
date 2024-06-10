package com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.domain.User;
// import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.domain.User;
public interface UserRepo extends JpaRepository<User, Long>{
    User findByUsername(String username);
}
