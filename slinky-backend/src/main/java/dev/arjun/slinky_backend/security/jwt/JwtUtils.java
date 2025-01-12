package dev.arjun.slinky_backend.security.jwt;

import dev.arjun.slinky_backend.service.UserDetailsImpl;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtUtils {
    @Value("${jwt.Secret}")
    private String jwtSecret;
    @Value("${jwt.ExpirationMs}")
    private int jwtExpirationMs;
    //Bearer <TOKEN>
    //Need to extract token from header
    public String getJwtFromRequest(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if(bearerToken!=null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return null;
    }
    //Method to generate token
    public String generateToken(UserDetailsImpl userDetails){
        String username = userDetails.getUsername();
        String roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority()).collect(Collectors.joining(","));
        return Jwts.builder()
                .subject(username)
                .claim("roles",roles)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime()+jwtExpirationMs))
                .signWith(key())
                .compact();
    }
    public String getUsernameFromToken(String token){
        return Jwts.parser().verifyWith((SecretKey) key())
                .build().parseSignedClaims(token).getPayload().getSubject();
    }
    public boolean validateToken(String token){
        try{
            Jwts.parser().verifyWith((SecretKey) key())
            .build().parseSignedClaims(token);
            return true;
        }catch (JwtException e){
            throw new RuntimeException(e);
        } catch (IllegalArgumentException e){
            throw new RuntimeException(e);
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }
    private Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }
}
