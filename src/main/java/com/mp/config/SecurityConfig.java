package com.mp.config;

import com.mp.security.CustomUserDetailsService;
import com.mp.security.JwtAuthenticationFilter;
import com.mp.security.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    public SecurityConfig(CustomUserDetailsService userDetailsService, JwtUtil jwtUtil) {
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
    }

    // --------- Authentication / Password beans ----------
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider prov = new DaoAuthenticationProvider();
        prov.setUserDetailsService(userDetailsService);
        prov.setPasswordEncoder(passwordEncoder());
        return prov;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // --------- JWT Filter bean ----------
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtUtil, userDetailsService);
    }

    // --------- CORS config ----------
    // Update these origins to match your frontends. Keep exact origins when allowCredentials(true).
    private static final List<String> ALLOWED_ORIGINS = List.of(
            "https://m-p-sharda.onrender.com",   // frontend production origin
            "https://m-p-sharda-b.onrender.com", // backend domain if you need it
            "http://localhost:4200"              // dev origin
    );

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(ALLOWED_ORIGINS); // explicit list (required when allowCredentials=true)
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // --------- Security filter chain ----------
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(Customizer.withDefaults()) // uses corsConfigurationSource()
            .csrf().disable()
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authz -> authz
                // Allow preflight requests
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                // Public endpoints
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/stats/**").permitAll()
                .requestMatchers("/api/institutions/**").permitAll()
                .requestMatchers("/api/quizzes/**").permitAll()
                .requestMatchers("/api/questions/**").permitAll()
                .requestMatchers("/ping", "/actuator/health").permitAll()

                // Allow uploads and H2 console and error page
                .requestMatchers("/uploads/**").permitAll()
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/error").permitAll()

                // Protected endpoints (example)
                .requestMatchers("/api/results/**").authenticated()

                // everything else authenticated
                .anyRequest().authenticated()
            );

        // allow frames for H2 console
        http.headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));

        // register JWT filter before UsernamePasswordAuthenticationFilter
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        // register DaoAuthenticationProvider so AuthenticationManager can use it
        http.authenticationProvider(daoAuthenticationProvider());

        return http.build();
    }
}
