package com.ead.serviceregistry.configs

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
class WebSecurityConfig {

    @Value("\${ead.serviceRegistry.username}")
    lateinit var username: String

    @Value("\${ead.serviceRegistry.password}")
    lateinit var password: String

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .httpBasic()
            .and()
            .authorizeRequests()
            .anyRequest()
            .authenticated()
            .and()
            .csrf()
            .disable()
            .formLogin()
        return http.build()
    }

    @Bean
    fun userDetailsService(): InMemoryUserDetailsManager {
        val user = User
            .withUsername(username)
            .password(passwordEncoder().encode(password))
            .roles("ADMIN")
            .build()
        return InMemoryUserDetailsManager(user)
    }

    @Bean
    fun passwordEncoder() = BCryptPasswordEncoder()
}