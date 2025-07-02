package com.dra.oauth2_google_jwt_app.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Controller;
import com.dra.oauth2_google_jwt_app.config.jwt.JwtAuthFilter;
import com.dra.oauth2_google_jwt_app.config.jwt.JwtUtil;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;

@Controller
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    @Value("${app.success-login-redirect-uri}")
    private String successLoginRedirectUri;

    private final JwtAuthFilter jwtAuthFilter;
    private final JwtUtil jwtUtil;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                                            .requestMatchers("auth/**").permitAll()
                                            .anyRequest().authenticated())
            .addFilterBefore(this.jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .oauth2Login(
                oauth2  -> oauth2.successHandler(authenticationSuccessHandler())
                                .failureHandler(authenticationFailureHandler())
            );
        return httpSecurity.build();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(){
        return (request, response, authentication) -> {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
            OAuth2User user = token.getPrincipal();
            String email = user.getAttribute("email");

            // Get new access token and refresh token
            String accessToken = this.jwtUtil.generateToken(email, false);
            String refreshToken = this.jwtUtil.generateToken(email, true);

            // Save created tokens as session cookies
            response.addCookie(this.getTokenCookie("access_token", accessToken));
            response.addCookie(this.getTokenCookie("refresh_token", refreshToken));

            response.sendRedirect(this.successLoginRedirectUri);
        };
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler(){
         return (request, rresponsees, exception) -> {
            System.out.println("OAuth2 login failed: " + exception.getMessage());
        };
    }

    private Cookie getTokenCookie(String name, String value){
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        return cookie;
    }

}
