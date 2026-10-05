// NSAT Demo Vulnerable Application — Java Spring Boot Auth Service
// This file intentionally contains security vulnerabilities for NSAT demo purposes.
// DO NOT use in production.

package com.example.auth;

import org.springframework.web.bind.annotation.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@RestController
@RequestMapping("/auth")
public class AuthService {

    // NSAT-TARGET: Weak cryptographic hash — MD5 for password storage
    public String hashPassword(String password) throws NoSuchAlgorithmException {
        // VULN: MD5 is cryptographically broken — use Argon2id or bcrypt instead
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    // NSAT-TARGET: Command injection via Runtime.exec with unsanitized input
    @PostMapping("/audit-log")
    public String runAuditCommand(@RequestParam String logEntry) throws Exception {
        // VULN: User-controlled string passed directly to Runtime.exec
        String cmd = "grep " + logEntry + " /var/log/app.log";
        Process p = Runtime.getRuntime().exec(cmd);
        return "Executed";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) throws Exception {
        // No rate limiting — vulnerable to brute force / credential stuffing
        String hashed = hashPassword(password);
        if ("admin".equals(username) && "5f4dcc3b5aa765d61d8327deb882cf99".equals(hashed)) {
            return "LOGIN_SUCCESS";
        }
        return "INVALID";
    }
}
