package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.security.MessageDigest;

@RestController
public class ApiController {

    @GetMapping("/api/data")
    public String foo(@RequestParam("x1") String x1) throws Exception {
        // Meaningless identifier foo(x1) calling Runtime.getRuntime().exec
        Runtime.getRuntime().exec(x1);
        MessageDigest md = MessageDigest.getInstance("MD5");
        return "processed";
    }
}
