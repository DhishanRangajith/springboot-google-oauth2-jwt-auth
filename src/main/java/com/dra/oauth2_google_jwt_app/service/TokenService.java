package com.dra.oauth2_google_jwt_app.service;

import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import com.dra.oauth2_google_jwt_app.config.jwt.JwtUtil;
import com.dra.oauth2_google_jwt_app.exception.CustomeException;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtUtil jwtUtil;

    public String getNewAccessTokenByRefreshToken(String refreshToken){
        if(refreshToken.isBlank()) throw new CustomeException("Missing refresh token.");
        try{
            if(this.jwtUtil.validateToken(refreshToken)){
                String email = this.jwtUtil.getUserEmailFromJWT(refreshToken);
                String accessToken = this.jwtUtil.generateToken(email, false);
                return accessToken;
            }else{
                throw new CustomeException("Refresh token is invalid.");
            }

        }catch(AuthenticationException ex){
            throw new CustomeException("Refresh token validation issues.");
        }
    }

}
