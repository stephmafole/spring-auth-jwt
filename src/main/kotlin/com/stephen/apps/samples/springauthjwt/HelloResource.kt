package com.stephen.apps.samples.springauthjwt

import com.stephen.apps.samples.springauthjwt.models.AuthenticationRequest
import com.stephen.apps.samples.springauthjwt.models.AuthenticationResponse
import com.stephen.apps.samples.springauthjwt.service.CustomUserDetailService
import com.stephen.apps.samples.springauthjwt.util.JwtUtil
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class HelloResource(
    private val authenticationManager: AuthenticationManager,
    private val customUserDetailService: CustomUserDetailService,
    private val jwtUtil: JwtUtil
) {

    @RequestMapping("/hello")
    fun hello(): String = "Hello World !!!"

    @PostMapping("/authenticate")
    fun createAuthenticationToken(@RequestBody authenticationRequest: AuthenticationRequest): ResponseEntity<Any> {
        return if (authenticationRequest.username.isEmpty() || authenticationRequest.password.isEmpty()) {
            ResponseEntity.badRequest().body("Invalid credentials")
        } else {
            try {
                authenticationManager.authenticate(UsernamePasswordAuthenticationToken(authenticationRequest.username, authenticationRequest.password))
                val userDetails = customUserDetailService.loadUserByUsername(authenticationRequest.username)
                val jwt = jwtUtil.generateToken(userDetails)
                ResponseEntity.ok(AuthenticationResponse(jwt))
            } catch (e: BadCredentialsException) {
                ResponseEntity.badRequest().body("Invalid credentials")
            }
        }
    }
}