package com.prgrms.devcourse.configures;

import com.prgrms.devcourse.jwt.Jwt;
import com.prgrms.devcourse.jwt.JwtAuthenticationFilter;
import com.prgrms.devcourse.jwt.JwtAuthenticationProvider;
import com.prgrms.devcourse.jwt.JwtSecurityContextRepository;
import com.prgrms.devcourse.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final JwtConfigure jwtConfigure;

    public WebSecurityConfigure(JwtConfigure jwtConfigure) {
        this.jwtConfigure = jwtConfigure;
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/assets/**", "/h2-console/**");
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("ACCESS DENIED");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public Jwt jwt() {
        return new Jwt(
                jwtConfigure.getIssuer(),
                jwtConfigure.getClientSecret(),
                jwtConfigure.getExpirySeconds()
        );
    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider(UserService userService, Jwt jwt) {
        return new JwtAuthenticationProvider(jwt, userService);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Autowired
    public void configureAuthentication(AuthenticationManagerBuilder builder, JwtAuthenticationProvider authenticationProvider) {
        builder.authenticationProvider(authenticationProvider);
    }

    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        Jwt jwt = getApplicationContext().getBean(Jwt.class);
        return new JwtAuthenticationFilter(jwtConfigure.getHeader(), jwt);
    }

    public SecurityContextRepository securityContextRepository() {
        Jwt jwt = getApplicationContext().getBean(Jwt.class);
        return new JwtSecurityContextRepository(jwtConfigure.getHeader(), jwt);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                  .antMatchers("/api/user/me").hasAnyRole("USER", "ADMIN")
//                .antMatchers("/admin").access("isFullyAuthenticated() and hasRole('ADMIN')")
                  .anyRequest().permitAll()
//                  .accessDecisionManager(accessDecisionManager())
//                  .expressionHandler(securityExpressionHandler())
                  .and()
                .csrf()
                  .disable()
                .headers()
                  .disable()
                .formLogin()
                  .disable()
//                .defaultSuccessUrl("/")
//                  .loginPage("/my-login")
//                  .usernameParameter("my-username")
//                  .passwordParameter("my-password")
//                .permitAll()
//                .and()
                .httpBasic()
                  .disable()

                .rememberMe()
                  .disable()
//                  .rememberMeParameter("remember-me") // 체크박스
//                  .tokenValiditySeconds(300)
//                  .and()
                .logout()
                  .disable()
//                  .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//                  .logoutSuccessUrl("/")
//                  .invalidateHttpSession(true)
//                  .clearAuthentication(true)
//                  .and()
                .sessionManagement()
                  .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                  .and()
//                .requiresChannel()
//                  .antMatchers("/api/**").requiresSecure();
//                  .anyRequest().requiresSecure()
//                  .and()
//                .anonymous()
//                  .principal("thisIsAnonymousUser")
//                  .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
//                  .and()
//                .sessionManagement()
//                .sessionFixation().changeSessionId()
//                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
//                .invalidSessionUrl("/")
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(false).and()
//                .and()
                .exceptionHandling()
                  .accessDeniedHandler(accessDeniedHandler())
                  .and()
                .securityContext()
                  .securityContextRepository(securityContextRepository())
                  .and()
//                .addFilterAfter(jwtAuthenticationFilter(), SecurityContextHolderFilter.class)
        ;
    }

    //    @Bean
//    public AccessDecisionManager accessDecisionManager() {
//        List<AccessDecisionVoter<?>> voters = new ArrayList<>();
//        voters.add(new WebExpressionVoter());
//        voters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));
//
//        return new UnanimousBased(voters);
//    }

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

}