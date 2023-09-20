package org.zerock.b01.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.zerock.b01.security.CustomUserDetailsService;
import org.zerock.b01.security.handler.Custom403Handler;

import javax.sql.DataSource;

//@RequiredArgsConstructor
@Log4j2 //로그 실행 명시
@Configuration // 환경설정 파일 명시
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class CustomSecurityConfig {

    //자동 로그인을 위한 주입
    private final DataSource dataSource;
    private final CustomUserDetailsService userDetailsService;
    @Bean
    public PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }

    @Bean
    public  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        log.info("===========================환경섫정===========================");

        //커스텀 로그인 페이지
        http.formLogin().loginPage("/member/login");
        //csrf() 토큰 비활성화
        http.csrf().disable();

        http.rememberMe()
                .key("12345678")
                .tokenRepository(persistentTokenRepository())
                .userDetailsService(userDetailsService)
                .tokenValiditySeconds(60*60*24*30);
        //403
        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler());
        return http.build();
    }


//정적 자원 처리
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        log.info("===========================웹 환경설정===========================");
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
        repo.setDataSource(dataSource);
        return repo;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        return new Custom403Handler();
    }
}



