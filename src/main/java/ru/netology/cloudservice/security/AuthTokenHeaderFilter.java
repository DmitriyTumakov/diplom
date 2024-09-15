package ru.netology.cloudservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.netology.cloudservice.repository.AuthorityRepository;
import ru.netology.cloudservice.repository.UserRepository;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

@Component
public class AuthTokenHeaderFilter extends OncePerRequestFilter {
    private final String AUTH_TOKEN = "auth-token";
    public final String BEARER_PREFIX = "Bearer ";
    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;

    public AuthTokenHeaderFilter(UserRepository userRepository, AuthorityRepository authorityRepository) {
        this.userRepository = userRepository;
        this.authorityRepository = authorityRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(AUTH_TOKEN);

        if (StringUtils.isEmpty(authHeader)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (authHeader.startsWith(BEARER_PREFIX)) {
            authHeader = authHeader.substring(BEARER_PREFIX.length());
        }

        if (userRepository.existsByToken(authHeader)) {
            SecurityContext context = SecurityContextHolder.createEmptyContext();

            UserDetails userDetails = userRepository.findByToken(authHeader);

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    authorityRepository.findAllByUsername(userDetails.getUsername())
            );

            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            context.setAuthentication(authToken);
            SecurityContextHolder.setContext(context);
        }
        filterChain.doFilter(request, response);
    }
}
