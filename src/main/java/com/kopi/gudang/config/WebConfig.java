package com.kopi.gudang.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private AuthInterceptor authInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns(
                        "/login",
                        "/logout",
                        "/css/**",
                        "/js/**",
                        "/images/**",
                        "/favicon.ico",
                        "/webjars/**",
                        "/error",
                        "/manifest.json",
                        "/service-worker.js",
                        "/register",
                        "/register/process",
                        "/verify-otp",
                        "/verify-otp/process",
                        "/forgot-password",
                        "/forgot-password/process",
                        "/reset-password",
                        "/reset-password/process");
    }
}
