package com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.filter.CustomAuthorizationFilter;
import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.filter.CustomeAuthenticationFilter;
import com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.service.CustomUserDetailsService;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    @Bean
    UserDetailsService userDetailsService() {
        return new CustomUserDetailsService();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    // Good newest, authorize basically
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        CustomeAuthenticationFilter customeAuthenticationFilter = new CustomeAuthenticationFilter(
                authenticationProvider());
        customeAuthenticationFilter.setFilterProcessesUrl("/api/login");
        http.authenticationProvider(authenticationProvider());
        http.cors().and().csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeHttpRequests()
                .requestMatchers("/api/hello", "api/login/**", "/api/token/refresh/**").permitAll() // Public endpoint
                .requestMatchers("/api/admin/**").hasAnyAuthority("ADMIN", "SUPER_ADMIN")
                .requestMatchers("/api/user/**").hasAnyAuthority("USER")
                .requestMatchers("/api/manager/**").hasAnyAuthority("MANAGER")
                .anyRequest().authenticated() // Any other request must be authenticated
                .and()
                .formLogin() // Form-based authentication
                .and()
                .httpBasic().and()
                .addFilter(customeAuthenticationFilter)
                .addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);// HTTP
                                                                                                              // Basic
                                                                                                              // authentication
        // http.addFilter(customeAuthenticationFilter);
        // http.addFilterBefore(new CustomAuthorizationFilter(),
        // UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}

// // Good newest, authorize basically
// @Bean
// public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
// http.authenticationProvider(authenticationProvider());
// http.cors().and().csrf().disable()
// .authorizeHttpRequests()
// .requestMatchers("/api/hello").permitAll() // Public endpoint
// .requestMatchers("/api/role/**").hasAnyAuthority("SUPER_ADMIN")
// .anyRequest().authenticated() // Any other request must be authenticated
// .and()
// .formLogin() // Form-based authentication
// .and()
// .httpBasic(); // HTTP Basic authentication
// http.addFilter(new CustomeAuthenticationFilter(authenticationProvider()));

// return http.build();
// }
