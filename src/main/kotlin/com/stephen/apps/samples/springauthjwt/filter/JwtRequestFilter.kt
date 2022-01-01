package com.stephen.apps.samples.springauthjwt.filter

import com.stephen.apps.samples.springauthjwt.service.CustomUserDetailService
import com.stephen.apps.samples.springauthjwt.util.JwtUtil
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class JwtRequestFilter(
    private val customUserDetailService: CustomUserDetailService,
    private val jwtUtil: JwtUtil
) : OncePerRequestFilter() {

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val authorizationHeader: String? = request.getHeader("Authorization")
        val jwt = extractJwt(authorizationHeader)
        val username = extractUsername(jwt)

        if (username.isNotBlank() && SecurityContextHolder.getContext().authentication == null) {
            val userDetails = customUserDetailService.loadUserByUsername(username)
            if (jwtUtil.validateToken(jwt, userDetails)) {
                saveAuthenticatedUserDetails(userDetails, request)
            }
        }

        filterChain.doFilter(request, response)
    }

    private fun extractJwt(authorizationHeader: String?) =
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            authorizationHeader.substring(7)
        } else {
            ""
        }

    private fun extractUsername(jwt: String) =
        if (jwt.isNotBlank()) {
            jwtUtil.extractUsername(jwt)
        } else {
            ""
        }

    private fun saveAuthenticatedUserDetails(userDetails: UserDetails, request: HttpServletRequest) {
        val usernamePasswordAuthenticationToken =
            UsernamePasswordAuthenticationToken(userDetails, null, userDetails.authorities)
        usernamePasswordAuthenticationToken.details = WebAuthenticationDetailsSource().buildDetails(request)
        SecurityContextHolder.getContext().authentication = usernamePasswordAuthenticationToken
    }
}
