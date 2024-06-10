package com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.service;
import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.domain.User;

import java.util.List;

import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.domain.Role;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);

    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User>getUsers();
    List<Role>getRoles();

}
