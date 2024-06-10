package com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.domain.Role;
import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.domain.User;
import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.repo.RoleRepo;
import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.repo.UserRepo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public User saveUser(User user) {
        //log.info("Saving new user {} to the database", user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    @Transactional
    public Role saveRole(Role role) {
        //log.info("Saving new role {} to the database", role.getName());
        return roleRepo.save(role);
    }

    @Override
    @Transactional
    public void addRoleToUser(String username, String roleName) {
        //log.info("Adding role {} to user {}", roleName, username);
        User user = userRepo.findByUsername(username);
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        //log.info("Fetching user {}", username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        //log.info("Fetching all users");
        return userRepo.findAll();
    }

    @Override
    public List<Role> getRoles() {
        // TODO Auto-generated method stub
        return roleRepo.findAll();
    }

   

}
