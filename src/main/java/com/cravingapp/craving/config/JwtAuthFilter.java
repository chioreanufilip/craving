package com.cravingapp.craving.config;

import com.cravingapp.craving.service.JwtService;
import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // 1. Ia header-ul "Authorization"
        final String authHeader = request.getHeader("Authorization");

        // 2. Verifică dacă e gol sau dacă nu începe cu "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); // Lasă cererea să meargă mai departe
            return;
        }

        // 3. Extrage token-ul (fără "Bearer ")
        final String jwt = authHeader.substring(7);

        // 4. Extrage username-ul
        final String username = jwtService.extractUsername(jwt);

        // 5. Verifică dacă email-ul e valid ȘI dacă user-ul nu e deja autentificat
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {


            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // 7. Verifică dacă token-ul e valid
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // 8. Creează un obiect de autentificare
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // 9. Setează utilizatorul ca "autentificat"
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // 10. Predă controlul următorului filtru din lanț
        filterChain.doFilter(request, response);
    }

//    @Override
//    protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response, jakarta.servlet.FilterChain filterChain) throws jakarta.servlet.ServletException, IOException {
//
//    }
}
