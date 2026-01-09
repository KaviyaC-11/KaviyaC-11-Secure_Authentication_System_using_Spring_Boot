package com.secureauth.secureauth.dao;

import com.secureauth.secureauth.model.User;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public class UserDAO {

    private final JdbcTemplate jdbcTemplate;

    // Constructor injection
    public UserDAO(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /* =========================================================
       USER LOOKUP
       ========================================================= */

    /**
     * Fetch user by email.
     * Returns User object if found, otherwise null.
     */
    public User findByEmail(String email) {

        String sql = "SELECT * FROM users WHERE email = ?";

        try {
            return jdbcTemplate.queryForObject(
                    sql,
                    new BeanPropertyRowMapper<>(User.class),
                    email
            );
        } catch (EmptyResultDataAccessException e) {
            // No user found for given email
            return null;
        }
    }

    /* =========================================================
       REGISTER
       ========================================================= */

    /**
     * Saves a new user during registration.
     */
    public void save(User user) {

        String sql =
                "INSERT INTO users (email, password, otp, verified, otp_created_at) " +
                "VALUES (?, ?, ?, ?, ?)";

        jdbcTemplate.update(
                sql,
                user.getEmail(),
                user.getPassword(),
                user.getOtp(),
                user.isVerified(),
                LocalDateTime.now()
        );
    }

    /* =========================================================
       OTP VERIFICATION
       ========================================================= */

    /**
     * Verifies email OTP and marks user as verified.
     * OTP expires after 5 minutes.
     */
    public boolean verifyOtp(String email, String otp) {

        String sql =
                "SELECT otp_created_at FROM users " +
                "WHERE email = ? AND otp = ? AND verified = false";

        List<LocalDateTime> times = jdbcTemplate.query(
                sql,
                (rs, rowNum) ->
                        rs.getTimestamp("otp_created_at").toLocalDateTime(),
                email,
                otp
        );

        // No matching OTP found
        if (times.isEmpty()) {
            return false;
        }

        LocalDateTime createdAt = times.get(0);

        // ⏱ OTP expiry check (5 minutes)
        if (createdAt.plusMinutes(5).isBefore(LocalDateTime.now())) {
            return false;
        }

        // Mark user as verified and clear OTP
        jdbcTemplate.update(
                "UPDATE users SET verified = true, otp = NULL, otp_created_at = NULL WHERE email = ?",
                email
        );

        return true;
    }

    /* =========================================================
       RESEND / UPDATE OTP
       ========================================================= */

    /**
     * Updates OTP for email verification (unused but safe).
     */
    public boolean updateOtpForVerification(String email, String newOtp) {

        String sql =
                "UPDATE users " +
                "SET otp = ?, otp_created_at = ? " +
                "WHERE email = ? AND verified = false";

        int updated = jdbcTemplate.update(
                sql,
                newOtp,
                LocalDateTime.now(),
                email
        );

        return updated > 0;
    }

    /**
     * Resends OTP if user exists and is not verified.
     */
    public boolean resendOtp(String email, String otp) {

        String sql =
                "UPDATE users SET otp = ?, otp_created_at = ? " +
                "WHERE email = ? AND verified = false";

        int updated = jdbcTemplate.update(
                sql,
                otp,
                LocalDateTime.now(),
                email
        );

        return updated > 0;
    }

    /* =========================================================
       PASSWORD RESET
       ========================================================= */

    /**
     * Creates OTP for password reset.
     */
    public boolean createPasswordResetOtp(String email, String otp) {

        String sql =
                "UPDATE users SET reset_otp = ?, reset_otp_created_at = ? " +
                "WHERE email = ?";

        return jdbcTemplate.update(
                sql,
                otp,
                LocalDateTime.now(),
                email
        ) > 0;
    }

    /**
     * Resets password using OTP.
     * OTP expires after 5 minutes.
     */
    public boolean resetPassword(String email, String otp, String newPassword) {

        String sql =
                "SELECT reset_otp_created_at FROM users " +
                "WHERE email = ? AND reset_otp = ?";

        List<LocalDateTime> times = jdbcTemplate.query(
                sql,
                (rs, rowNum) ->
                        rs.getTimestamp("reset_otp_created_at").toLocalDateTime(),
                email,
                otp
        );

        if (times.isEmpty()) {
            return false;
        }

        LocalDateTime createdAt = times.get(0);

        // ⏱ OTP expiry check
        if (createdAt.plusMinutes(5).isBefore(LocalDateTime.now())) {
            return false;
        }

        // Update password and clear reset OTP
        jdbcTemplate.update(
                "UPDATE users SET password = ?, reset_otp = NULL, reset_otp_created_at = NULL WHERE email = ?",
                newPassword,
                email
        );

        return true;
    }

    /* =========================================================
       DELETE ACCOUNT
       ========================================================= */

    /**
     * Deletes user account using email.
     */
    public boolean deleteByEmail(String email) {

        String sql = "DELETE FROM users WHERE email = ?";

        return jdbcTemplate.update(sql, email) > 0;
    }
}
