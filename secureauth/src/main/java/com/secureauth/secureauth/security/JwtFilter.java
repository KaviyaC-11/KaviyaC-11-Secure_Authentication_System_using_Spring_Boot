package com.secureauth.secureauth.security;

import com.secureauth.secureauth.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        /* =========================================================
           CORS HEADERS (MUST BE FIRST)
           ========================================================= */
        response.setHeader("Access-Control-Allow-Origin", "http://127.0.0.1:5501");
        response.setHeader(
                "Access-Control-Allow-Methods",
                "GET,POST,PUT,DELETE,OPTIONS"
        );
        response.setHeader(
                "Access-Control-Allow-Headers",
                "Authorization,Content-Type"
        );
        response.setHeader("Access-Control-Allow-Credentials", "true");

        /* =========================================================
           ALLOW PREFLIGHT REQUESTS (CRITICAL)
           ========================================================= */
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        String path = request.getRequestURI();

        /* =========================================================
           PUBLIC ENDPOINTS (NO JWT REQUIRED)
           ========================================================= */
        if (path.equals("/api/auth/login") ||
            path.equals("/api/auth/register") ||
            path.equals("/api/auth/verify-otp") ||
            path.equals("/api/auth/resend-otp") ||
            path.equals("/api/auth/forgot-password") ||
            path.equals("/api/auth/reset-password")) {

            filterChain.doFilter(request, response);
            return;
        }

        /* =========================================================
           JWT VALIDATION (PROTECTED ENDPOINTS)
           ========================================================= */
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Missing or invalid Authorization header");
            return;
        }

        String token = authHeader.substring(7);
        String email = JwtUtil.validateToken(token);

        if (email == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid or expired token");
            return;
        }

        // Attach authenticated email
        request.setAttribute("authenticatedEmail", email);

        filterChain.doFilter(request, response);
    }
}
