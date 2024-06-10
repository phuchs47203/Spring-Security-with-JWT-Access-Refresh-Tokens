package com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.domain.Role;
import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.domain.User;
import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.repo.UserRepo;
import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@SpringBootApplication
@Slf4j
@RequiredArgsConstructor
public class SpringSecurityWithJwtAccessRefreshTokensApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityWithJwtAccessRefreshTokensApplication.class, args);
	}

	@Bean
	CommandLineRunner run(UserService userService)
	{
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

		return args ->{
			userService.saveRole(new Role(null, "USER"));
			userService.saveRole(new Role(null, "MANAGER"));
			userService.saveRole(new Role(null, "ADMIN"));
			userService.saveRole(new Role(null, "SUPER_ADMIN"));
			
			userService.saveUser(new User(null, "Phuc Hoang", "phuc", "1", new ArrayList<>()));
			userService.saveUser(new User(null, "Nhat Long", "long", "1", new ArrayList<>()));
			userService.saveUser(new User(null, "Viet Hoang", "hoang", "1", new ArrayList<>()));
			userService.saveUser(new User(null, "Le Phong", "phong", "1", new ArrayList<>()));
			

			userService.addRoleToUser("phuc","ADMIN");
			userService.addRoleToUser("long","MANAGER");
			userService.addRoleToUser("hoang","USER");
			userService.addRoleToUser("phong","ADMIN");
			userService.addRoleToUser("phong","SUPER_ADMIN");
			userService.addRoleToUser("phong","USER");


		};
	}
}
