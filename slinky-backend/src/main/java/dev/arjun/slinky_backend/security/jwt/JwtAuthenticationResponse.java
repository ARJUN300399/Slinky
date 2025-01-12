package dev.arjun.slinky_backend.security.jwt;

import lombok.Data;

@Data
public class JwtAuthenticationResponse {
    private String token;
}
