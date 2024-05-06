package com.mustafa.basicauth.security;

import com.mustafa.basicauth.model.Role;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity, HandlerMappingIntrospector introspector)
            throws Exception{

        // h2 hatasi icin kullaniliyor
        MvcRequestMatcher.Builder mvcRequestMatcher = new MvcRequestMatcher.Builder(introspector);

        httpSecurity
                .headers(x -> x.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
               // .csrf(AbstractHttpConfigurer::disable)
                .csrf(csrfConfig -> csrfConfig.ignoringRequestMatchers(mvcRequestMatcher.pattern("/public/**"))
                        .ignoringRequestMatchers(PathRequest.toH2Console()))
                .authorizeHttpRequests(x -> x
                        .requestMatchers(mvcRequestMatcher.pattern("/public/**")).permitAll()
                        .requestMatchers(mvcRequestMatcher.pattern("/private/admin/**")).hasRole(Role.ROLE_ADMIN.getValue())
                        .requestMatchers(mvcRequestMatcher.pattern("/private/**")).hasAnyRole(Role.ROLE_USER.getValue(),
                                Role.ROLE_ADMIN.getValue(),
                                Role.ROLE_FSK.getValue())
                        .requestMatchers(PathRequest.toH2Console()).hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(Customizer.withDefaults());

        return httpSecurity.build();
    }
}
