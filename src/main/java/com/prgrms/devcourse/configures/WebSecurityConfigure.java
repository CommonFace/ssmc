package com.prgrms.devcourse.configures;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private DataSource dataSource;

    @Autowired
    public void setDataSource(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .usersByUsernameQuery(
                        "SELECT " +
                                "login_id, passwd, true " +
                        "FROM " +
                                "users " +
                        "WHERE " +
                                "login_id = ?"
                )
                .groupAuthoritiesByUsername(
                        "SELECT " +
                                "u.login_id, g.name, p.name " +
                        "FROM " +
                                "users u JOIN groups g ON u.group_id = g.id " +
                                "LEFT JOIN group_permission gp ON g.id = gp.group_id " +
                                "JOIN permissions p ON p.id = gp.permission_id " +
                        "WHERE " +
                                "u.login_id = ?"
                )
                .getUserDetailsService().setEnableAuthorities(false)
        ;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    @Qualifier("myAsyncTaskExecutor")
//    public ThreadPoolTaskExecutor threadPoolTaskExecutor() {
//        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
//        executor.setCorePoolSize(3);
//        executor.setMaxPoolSize(5);
//        executor.setThreadNamePrefix("my-executor-");
//        return executor;
//    }
//
//    @Bean
//    public DelegatingSecurityContextAsyncTaskExecutor taskExecutor(
//            @Qualifier("myAsyncTaskExecutor") ThreadPoolTaskExecutor delegate
//    ) {
//        return new DelegatingSecurityContextAsyncTaskExecutor(delegate);
//    }

//    public WebSecurityConfigure() {
//        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
//    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/assets/**", "/h2-console/**");
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("user").password("{noop}user123").roles("USER")
//                .and()
//                .withUser("admin01").password("{noop}admin123").roles("ADMIN")
//                .and()
//                .withUser("admin02").password("{noop}admin123").roles("ADMIN")
//        ;
//    }

    @Bean
    public AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<?>> voters = new ArrayList<>();
        voters.add(new WebExpressionVoter());
        voters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));

        return new UnanimousBased(voters);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                  .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                  .antMatchers("/admin").access("hasRole('ADMIN') and isFullyAuthenticated() and hasRole('ADMIN')")
                  .anyRequest().permitAll()
                  .accessDecisionManager(accessDecisionManager())
//                  .expressionHandler(securityExpressionHandler())
                  .and()
                .httpBasic()
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
