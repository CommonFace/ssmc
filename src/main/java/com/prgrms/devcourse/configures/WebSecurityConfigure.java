package com.prgrms.devcourse.configures;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/assets/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}user123").roles("USER")
                .and()
                .withUser("admin01").password("{noop}admin123").roles("ADMIN")
                .and()
                .withUser("admin02").password("{noop}admin123").roles("ADMIN")
        ;
    }

    public SecurityExpressionHandler<FilterInvocation> securityExpressionHandler() {
        return new CustomWebSecurityExpressionHandler(
                new AuthenticationTrustResolverImpl(),
                "ROLE_"
        );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                  .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                  .antMatchers("/admin").access("hasRole('ADMIN') and isFullyAuthenticated() and hasRole('ADMIN') and oddAdmin")
                  .anyRequest().permitAll()
                  .expressionHandler(securityExpressionHandler())
                  .and()
                .formLogin()
                  .defaultSuccessUrl("/")
//                  .loginPage("/my-login")
//                  .usernameParameter("my-username")
//                  .passwordParameter("my-password")
                  .permitAll()
                  .and()
                .rememberMe()
                  .rememberMeParameter("remember-me") // 체크박스
                  .tokenValiditySeconds(300)
                  .and()
                .logout()
                  .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                  .logoutSuccessUrl("/")
                  .invalidateHttpSession(true)
                  .clearAuthentication(true)
                  .and()
                .requiresChannel()
//                  .antMatchers("/api/**").requiresSecure();
                  .anyRequest().requiresSecure()
//                  .and()
//                .anonymous()
//                  .principal("thisIsAnonymousUser")
//                  .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
                  .and()
                .sessionManagement()
                  .sessionFixation().changeSessionId()
                  .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                  .invalidSessionUrl("/")
                  .maximumSessions(1)
                  .maxSessionsPreventsLogin(false).and()
                  .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
        ;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {

        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

}
