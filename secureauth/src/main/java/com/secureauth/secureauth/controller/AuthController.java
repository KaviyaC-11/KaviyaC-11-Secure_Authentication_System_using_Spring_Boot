package com.secureauth.secureauth.controller;

import com.secureauth.secureauth.dao.UserDAO;
import com.secureauth.secureauth.model.ApiResponse;
import com.secureauth.secureauth.model.User;
import com.secureauth.secureauth.service.EmailService;
import com.secureauth.secureauth.util.JwtUtil;
import com.secureauth.secureauth.util.OTPUtil;
import com.secureauth.secureauth.util.PasswordUtil;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * AuthController
 * ---------------
 * Handles all authentication-related APIs:
 * - Registration
 * - Email verification (OTP)
 * - Login
 * - Forgot / Reset password
 * - Delete account
 */
@RestController
@RequestMapping("/api/auth")
@CrossOrigin
public class AuthController {

    private final UserDAO userDAO;
    private final EmailService emailService;

    // Constructor injection
    public AuthController(UserDAO userDAO, EmailService emailService) {
        this.userDAO = userDAO;
        this.emailService = emailService;
    }

    /* =========================================================
       REGISTER
       ========================================================= */
    @PostMapping("/register")
public ResponseEntity<ApiResponse> register(
        @RequestParam String email,
        @RequestParam String password) {

    try {
        // Check if user already exists
        User existingUser = userDAO.findByEmail(email);

        // Generate OTP
        String otp = OTPUtil.generateOTP();

        // SAME email message for verification (defined ONCE)
        String emailBody =
                "Hello,\n\n" +
                "Use the following One-Time Password (OTP) to complete your SecureAuth verification:\n\n" +
                "OTP: " + otp + "\n\n" +
                "This code is valid for 5 minutes. Please keep it confidential.\n\n" +
                "If you did not request this code, you may safely ignore this message.\n\n" +
                "Best regards,\n" +
                "SecureAuth Team";

        /* ===============================
           CASE 1: NEW USER
        =============================== */
        if (existingUser == null) {

            String hashedPassword = PasswordUtil.hash(password);

            // Create new user (not verified)
            User user = new User(email, hashedPassword, otp, false);
            userDAO.save(user);

            // Send verification email
            emailService.sendEmail(
                    email,
                    "SecureAuth | Email Verification OTP",
                    emailBody
            );

            return ResponseEntity
                    .status(HttpStatus.CREATED)
                    .body(new ApiResponse("success", "OTP sent to email"));
        }

        /* ===============================
           CASE 2: EXISTING BUT NOT VERIFIED
        =============================== */
        if (!existingUser.isVerified()) {

            // Update OTP for existing user
            userDAO.updateOtpForVerification(email, otp);

            // Send SAME verification email
            emailService.sendEmail(
                    email,
                    "SecureAuth | Email Verification OTP",
                    emailBody
            );

            return ResponseEntity.ok(
                    new ApiResponse("success", "OTP sent to email")
            );
        }

        /* ===============================
           CASE 3: EXISTING AND VERIFIED
        =============================== */
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(new ApiResponse("error", "Account already exists"));

    } catch (Exception e) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiResponse("error", "Server error"));
    }
}

    /* =========================================================
       VERIFY OTP (EMAIL VERIFICATION)
       ========================================================= */
    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse> verifyOtp(
            @RequestParam String email,
            @RequestParam String otp) {

        boolean success = userDAO.verifyOtp(email, otp);

        if (success) {
            return ResponseEntity.ok(
                    new ApiResponse("success", "Email verified successfully")
            );
        }

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse("error", "Invalid OTP"));
    }

    /* =========================================================
       RESEND OTP
       ========================================================= */
    @PostMapping("/resend-otp")
    public ResponseEntity<ApiResponse> resendOtp(@RequestParam String email) {

        String otp = OTPUtil.generateOTP();
        boolean updated = userDAO.resendOtp(email, otp);

        if (!updated) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse("error", "User not found or already verified"));
        }

        String emailBody =
                "Hello,\n\n" +
                "Your New One-Time Password (OTP) for SecureAuth verification is:\n\n" +
                "OTP: " + otp + "\n\n" +
                "This code is valid for 5 minutes. Please keep it confidential.\n\n" +
                "If you did not request this code, you may safely ignore this message.\n\n" +
                "Best regards,\n" +
                "SecureAuth Team";

        emailService.sendEmail(
                email,
                "SecureAuth | Resend OTP",
                emailBody
        );

        return ResponseEntity.ok(
                new ApiResponse("success", "New OTP sent to email")
        );
    }

    /* =========================================================
       LOGIN
       ========================================================= */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse> login(
            @RequestParam String email,
            @RequestParam String password) {

        // Check if user exists
        User user = userDAO.findByEmail(email);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse("error", "Invalid email or password"));
        }

        // Validate password
        if (!PasswordUtil.hash(password).equals(user.getPassword())) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse("error", "Invalid email or password"));
        }

        // Check email verification
        if (!user.isVerified()) {
            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse("error", "Email not verified"));
        }

        // Generate JWT token
        String token = JwtUtil.generateToken(email);

        return ResponseEntity.ok(
                new ApiResponse("success", "Login successful", token)
        );
    }

    /* =========================================================
       FORGOT PASSWORD
       ========================================================= */
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse> forgotPassword(@RequestParam String email) {

        String otp = OTPUtil.generateOTP();
        boolean updated = userDAO.createPasswordResetOtp(email, otp);

        if (!updated) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse("error", "Email not found"));
        }

        String emailBody =
                "Hello,\n\n" +
                "Your Password Reset OTP for SecureAuth verification is:\n\n" +
                "OTP: " + otp + "\n\n" +
                "This code is valid for 5 minutes. Please keep it confidential.\n\n" +
                "If you did not request this code, you may safely ignore this message.\n\n" +
                "Best regards,\n" +
                "SecureAuth Team";

        emailService.sendEmail(
                email,
                "SecureAuth | Password Reset OTP",
                emailBody
        );

        return ResponseEntity.ok(
                new ApiResponse("success", "OTP sent to your email")
        );
    }

    /* =========================================================
       RESET PASSWORD
       ========================================================= */
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse> resetPassword(
            @RequestParam String email,
            @RequestParam String otp,
            @RequestParam String password) {

        // Validate password input
        if (password == null || password.trim().isEmpty()) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse("error", "Password cannot be empty"));
        }

        // Check password strength
        if (!PasswordUtil.isStrong(password)) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse("error", "Password does not meet requirements"));
        }

        // Reset password using OTP
        boolean success = userDAO.resetPassword(
                email,
                otp,
                PasswordUtil.hash(password)
        );

        if (!success) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse("error", "Invalid or expired OTP"));
        }

        return ResponseEntity.ok(
                new ApiResponse("success", "Password updated successfully")
        );
    }

    /* =========================================================
       DELETE ACCOUNT
       ========================================================= */
    @PostMapping("/delete-account")
    public ResponseEntity<ApiResponse> deleteAccount(HttpServletRequest request) {

        // Email is set by JwtFilter after token validation
        String email = (String) request.getAttribute("authenticatedEmail");

        if (email == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse("error", "Unauthorized"));
        }

        boolean deleted = userDAO.deleteByEmail(email);

        if (deleted) {
            return ResponseEntity.ok(
                    new ApiResponse("success", "Account deleted successfully")
            );
        }

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(new ApiResponse("error", "Account not found"));
    }
}
