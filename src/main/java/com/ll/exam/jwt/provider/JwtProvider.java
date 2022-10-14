package com.ll.exam.jwt.provider;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

//@Component
//public class JwtProvider {
//
//    private SecretKey cachedSecretKey;
//    @Value("${custom.jwt.secretKey}")
//    private String secretKeyPlain;
//
//    public SecretKey _getSecretKey() {
//        String keyBase64Encoded = Base64.getEncoder().encodeToString(secretKeyPlain.getBytes());
//        SecretKey secretKey = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
//
//        return secretKey;
//    }
//
//    public SecretKey getSecretKey() {
//        if (cachedSecretKey == null) {
//            cachedSecretKey = _getSecretKey();
//        }
//        return cachedSecretKey;
//    }
//}

@Component
@RequiredArgsConstructor
public class JwtProvider {
    private final SecretKey jwtSecretKey;

    private SecretKey getSecretKey() {
        return jwtSecretKey;
    }

    public String generateAccessToken(Map<String, Object> claims, int seconds) {
        long now = new Date().getTime();
        Date accessTokenExpire = new Date(now + 1000L * seconds);

        return Jwts.builder()
                .claim("body", Util.json.toStr(claims))
                .setExpiration(accessTokenExpire)
                .signWith(getSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    public boolean verify(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSecretKey())
                    .build()
                    .parseClaimsJws(token);
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public Map<String, Object> getClaims(String token) {
        String body = Jwts.parserBuilder()
                .setSigningKey(getSecretKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("body", String.class);

        return Util.json.toMap(body);
    }
}
