package com.dra.oauth2_google_jwt_app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Controller;

@Controller
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                    .oauth2Login(
                        oauth2  -> oauth2.successHandler(authenticationSuccessHandler())
                                          .failureHandler(authenticationFailureHandler())
                    );
        return httpSecurity.build();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(){
        return (req, res, authentication) -> {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
            OAuth2User user = token.getPrincipal();
            System.out.println("User Email: " + user.getAttribute("email"));
        };
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler(){
         return (req, res, exception) -> {
            System.out.println("OAuth2 login failed: " + exception.getMessage());
        };
    }

}
