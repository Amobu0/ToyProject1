package kr.co.farmstory.controller.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

//@EnableWebSecurity  지원중단
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{


        //이렇게 커스텀하고 나면 스프링 시큐리티의 기본 보안 설정 해제
        //특정 경로에 대한 인가 설정
        http.
                authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login").permitAll() // 모든 사용자 접근 허용
                        .requestMatchers("/").authenticated() //로그인만 진행하면 접근 허용
                        .requestMatchers("/").denyAll()// 모든 사용자 접근 불가
                        .requestMatchers("/admin/**").hasRole("ADMIN")// 로그인 한 뒤에 특정한 규칙이 있어야 허용
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "MANAGER")// 여거가지 규칙을 설정
                        .anyRequest().permitAll() // 위에서 처리하지 못한 나머지 경로를 처리
                );

        return http.build();
    }
}
