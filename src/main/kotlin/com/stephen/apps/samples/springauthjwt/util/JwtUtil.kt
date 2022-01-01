package com.stephen.apps.samples.springauthjwt.util

import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.*
import javax.crypto.SecretKey

@Service
class JwtUtil(
    @Value("\${jwt.signing.key.secret}")
    val keyChain: String = "",
    val key: SecretKey? = Keys.hmacShaKeyFor(keyChain.toByteArray()),
    @Value("\${jwt.token.expiration.seconds}")
    private val expirationTime: String = ""
) {
    fun generateToken(user: UserDetails): String {
        val expiration = LocalDateTime.now().plusSeconds(expirationTime.toLong()).atZone(ZoneId.systemDefault())
        return Jwts.builder().setSubject(user.username)
            .setAudience("audience")
            .setExpiration(Date.from(expiration.toInstant()))
            .signWith(key, SignatureAlgorithm.HS256)
            .setId(UUID.randomUUID().toString())
            .setIssuer("user-service")
            .setIssuedAt(Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant()))
            .compact()
    }

    fun extractUsername(token: String): String {
        return try {
            val claims = readToken(token).body
            claims.subject
        } catch (expiredJwtException: ExpiredJwtException) {
            ""
        }
    }

    private fun readToken(token: String): Jws<Claims> {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
    }

    fun validateToken(token: String, userDetails: UserDetails): Boolean {
        val username = extractUsername(token)
        return username == userDetails.username && tokenValid(token)
    }

    private fun tokenValid(token: String): Boolean {
        val claims = readToken(token).body
        return claims.expiration.after(Date())
    }
}