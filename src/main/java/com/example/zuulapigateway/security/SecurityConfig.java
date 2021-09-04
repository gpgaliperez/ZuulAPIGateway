package com.example.zuulapigateway.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors()
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "//**")
                .hasAuthority("administracion")
                .antMatchers(HttpMethod.POST, "//**")
                .hasAuthority("administracion")
                .antMatchers(HttpMethod.DELETE, "//**")
                .hasAuthority("administracion")
                .antMatchers(HttpMethod.PUT, "//**")
                .hasAuthority("administracion")

                .anyRequest().authenticated()
                .and().oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(new CustomJwtAuthenticationConverter());
    }
}