package com.dra.oauth2_google_jwt_app.controller;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.dra.oauth2_google_jwt_app.exception.CustomeException;
import com.dra.oauth2_google_jwt_app.service.TokenService;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("api/token")
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAccessToken(@RequestBody Map<String,String> data){
        try{
            String refreshToken = data.get("refreshToken");
            String newAccessToken = this.tokenService.getNewAccessTokenByRefreshToken(refreshToken);
            return ResponseEntity.ok(Map.of("accessToken",newAccessToken));
        }catch(CustomeException exception){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(exception.getMessage());
        }catch(Exception exception){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refreshing token error.");
        }
    }

}
