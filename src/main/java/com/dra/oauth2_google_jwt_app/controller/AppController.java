package com.dra.oauth2_google_jwt_app.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("api")
public class AppController {

    @GetMapping("home")
    public String getSomething() {
        return "Hello Wourld!";
    }

}
