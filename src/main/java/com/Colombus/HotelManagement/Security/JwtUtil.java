package com.Colombus.HotelManagement.Security;

import com.Colombus.HotelManagement.Models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.function.Function;

@Component
public class JwtUtil {
    private static final String SECRET_KEY_STRING = "your_very_long_secure_secret_key_that_is_32_bytes_or_more";
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(SECRET_KEY_STRING.getBytes());
    private static final long EXPIRATION_TIME = 1000 * 60 * 60; // 1 hour

    //  Generate Token (Fixed)
    public String generateToken(User user) {
        if (user == null || user.getUserName() == null) {
            throw new IllegalArgumentException("User cannot be null");
        }

        return Jwts.builder()
                .setSubject(user.getUserName())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY) //  FIXED SIGNING - Removed `SignatureAlgorithm`
                .compact();
    }

    //  Extract Username
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //  Extract Expiration Date
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //  Extract Any Claim (Fixed)
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claimsResolver.apply(claims);
    }

    // Validate Token
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    //  Check Expiration
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
}
