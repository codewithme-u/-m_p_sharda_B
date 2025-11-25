package com.mp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.nio.file.Paths;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOriginPatterns("*")     // allow all origins
                .allowedMethods("*")            // allow all HTTP methods
                .allowedHeaders("*")            // allow all headers
                .allowCredentials(true)         // allow cookies/tokens
                .maxAge(3600);                  // CORS preflight cache duration
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        String uploadPath = Paths.get(System.getProperty("user.dir"), "uploads")
                .toUri()
                .toString();

        System.out.println("=====================================");
        System.out.println("SERVING IMAGES FROM: " + uploadPath);
        System.out.println("=====================================");

        registry.addResourceHandler("/uploads/**")
                .addResourceLocations(uploadPath);
    }
}
