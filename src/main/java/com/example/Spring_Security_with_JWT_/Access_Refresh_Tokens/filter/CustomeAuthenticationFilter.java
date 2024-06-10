package com.example.Spring_Security_with_JWT_.Access_Refresh_Tokens.filter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomeAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationProvider authenticationProvider;

    public CustomeAuthenticationFilter(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is: {}", username);
        log.info("Password is: {}", password);
        
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationProvider.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authentication) throws IOException, ServletException {
        
            User user = (User)authentication.getPrincipal();
            Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
            String access_token = JWT.create()
                                    .withSubject(user.getUsername())
                                    .withExpiresAt(new Date(System.currentTimeMillis()+ 10*60*1000))
                                    .withIssuer(request.getRequestURL().toString())
                                    .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                                    .sign(algorithm);
            String refresh_token = JWT.create()
                                    .withSubject(user.getUsername())
                                    .withExpiresAt(new Date(System.currentTimeMillis()+ 60*60*1000))
                                    .withIssuer(request.getRequestURL().toString())
                                    .sign(algorithm);
            // response.setHeader("access_token", access_token);
            // response.setHeader("refresh_token", refresh_token);
            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", access_token);
            tokens.put("refresh_token", refresh_token);
             response.setContentType("application/json");
                 new ObjectMapper().writeValue(response.getOutputStream(), tokens);

    }

}
