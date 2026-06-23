package com.dlai.oidc.authserver

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests {
                it.requestMatchers("/authorize").authenticated()
                    .anyRequest().permitAll()
            }
            .formLogin {}
        return http.build()
    }
    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    fun userDetailsService(passwordEncoder: PasswordEncoder): UserDetailsService {
        val user = User.withUsername("test-user")
            .password(passwordEncoder.encode("password"))
            .roles("USER")
            .build()
        return InMemoryUserDetailsManager(user)
    }

}