package com.secureauth.secureauth.util;

import java.security.MessageDigest;

public class PasswordUtil {

    public static String hash(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashed = md.digest(password.getBytes());

            StringBuilder sb = new StringBuilder();
            for (byte b : hashed) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();

        } catch (Exception e) {
            throw new RuntimeException("Password hashing failed");
        }
    }

    public static boolean isStrong(String password) {
    return password != null &&
           password.matches("^(?=.*[A-Za-z])(?=.*\\d)(?=.*[!@#$%^&*_\\-()]).{6,}$");
}

}
