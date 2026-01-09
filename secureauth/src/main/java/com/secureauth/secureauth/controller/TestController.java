package com.secureauth.secureauth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/api/protected")
    public String protectedApi() {
        return "You have accessed a PROTECTED API 🎉";
    }
}
