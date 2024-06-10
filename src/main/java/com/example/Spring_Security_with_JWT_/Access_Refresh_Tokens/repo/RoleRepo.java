package com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.domain.Role;

public interface RoleRepo extends JpaRepository<Role, Long>{
    Role findByName(String name);
}
