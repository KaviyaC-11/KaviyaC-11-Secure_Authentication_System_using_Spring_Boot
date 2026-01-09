package com.secureauth.secureauth.model;

import java.time.LocalDateTime;

/**
 * User Model
 * ----------
 * Represents a user record from the `users` table.
 */
public class User {

    private Long id;
    private String email;
    private String password;
    private String otp;
    private boolean verified;
    private LocalDateTime otpCreatedAt;

    /**
     * Default constructor
     * Required for Spring JDBC mapping
     */
    public User() {
    }

    /**
     * Constructor used during registration
     */
    public User(String email, String password, String otp, boolean verified) {
        this.email = email;
        this.password = password;
        this.otp = otp;
        this.verified = verified;
        this.otpCreatedAt = LocalDateTime.now();
    }

    /* =======================
       GETTERS & SETTERS
       ======================= */

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }
 
    public void setEmail(String email) {
        this.email = email;
    }
 
    public String getPassword() {
        return password;
    }
 
    public void setPassword(String password) {
        this.password = password;
    }
 
    public String getOtp() {
        return otp;
    }
 
    public void setOtp(String otp) {
        this.otp = otp;
    }
 
    public boolean isVerified() {
        return verified;
    }
 
    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    public LocalDateTime getOtpCreatedAt() {
        return otpCreatedAt;
    }

    public void setOtpCreatedAt(LocalDateTime otpCreatedAt) {
        this.otpCreatedAt = otpCreatedAt;
    }
}
