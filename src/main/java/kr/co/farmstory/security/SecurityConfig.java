package kr.co.farmstory.security;

import kr.co.farmstory.oauth2.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


/**
 * 시큐리티는 경우 세부 버전별로 구현 방법이 많이 다르기 때문에 버전 마다 구현 특징을 확인해야한다.
 * <p>
 * 1. client 요청
 * 2. Servlet Container 는 여러개의 필터를 가지고 있고 요청은 필터를 통과해서 들어온다
 * 3. Spring Security 를 의존성으로 추가해 놓게 되면 Filter 에서 해당 요청을 가로챈다.
 *
 * @EnableWebSecurity 지원중단
 * <p>
 * 스프링 부트 3.1.X 부터 람다형식 표현 **필수**
 */

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {


        //이렇게 커스텀하고 나면 스프링 시큐리티의 기본 보안 설정 해제
        //특정 경로에 대한 인가 설정
        http.authorizeHttpRequests((auth) -> auth
//                                 hasRole 의 경우 DB role 필드에 꼭 "ROLE_ADMIN" 라고 적어야 적용
//                                 prefix > "ROLE_" 자동 생성
//                        .requestMatchers("/", "/admin/**").hasRole("ADMIN")

//                        .requestMatchers("/").authenticated() //로그인만 진행하면 접근 허용
//                        .requestMatchers("/").denyAll()// 모든 사용자 접근 불가
                .requestMatchers("/", "/user/login").permitAll() // 모든 사용자 접근 허용
                .requestMatchers("/admin/**").hasAuthority("ADMIN")
                .requestMatchers("/introduction/**").hasAuthority("MANAGER")
                .requestMatchers("/my/**").hasAnyRole("ADMIN", "MANAGER")// 여거가지 규칙을 설정
                .anyRequest().permitAll()); // 위에서 처리하지 못한 나머지 경로를 처리


        //로그인 설정
        http.formLogin((login) -> login
                .loginPage("/user/login")//오류 페이지로 갔을때 시큐리티가 로그인 페이지로 redirect
//                        .loginProcessingUrl("/user/login") // 로그인페이지에서 Post 요청으로 보낸 Id와 Pass 받아서 로그인 진행
                .defaultSuccessUrl("/")
                .failureUrl("/user/login?success=100") // 로그인 실패 후 이동 페이지
                .usernameParameter("uid") //아이디 파라미터명 설정
                .passwordParameter("pass") //비밀번호 파라미터명 설정
                .permitAll());

        //로그아웃 설정
        http.logout(logout -> logout
                .invalidateHttpSession(true)// session 무효화 -> logout 후 새로운 session 시작
                .logoutRequestMatcher(new AntPathRequestMatcher("/user/logout")) // logout 호출 URL
                .logoutSuccessUrl("/user/login?success=300"));

//       스프링 시큐리티에는 사이트 위변조 방지기술이 자동으로 등록되어 있다.
//       그렇게 되면 로그인 페이지에서 Post 요청을 보낼때 csrf Token도 보내주어야 로그인이 진행된다.
//       토큰을 보내지 않으면 로그인이 되지 않기 때문에 개발 환경에서만 csrf disable 시킨다
        http.csrf((auth) -> auth.disable());

        //다중 로그인
//        http.sessionManagement((auth) -> auth
//                .maximumSessions(1)
//                //true = 초과 시 새로운 로그인 차단
//                //false = 초과 시 기존 session 하나 삭제
//                .maxSessionsPreventsLogin(true));

        //세션 고정 보호
        http.sessionManagement((auth) -> auth
                .sessionFixation()
//                        로그인 시 동일한 세션에 대한 id 변경
                .changeSessionId());

        //OAuth 설정
        http.oauth2Login(config -> config
//                .loginPage("/user/login")
//                .defaultSuccessUrl("/")
                .userInfoEndpoint((userInfoEndpointConfig ->
                        userInfoEndpointConfig.userService(customOAuth2UserService))));

        return http.build();
    }


    //         시큐리티 암호화
//     스프링 시큐리티는 사용자 인증(로그인)시 비밀번호에 대해 단방향 해시 암호화를 진행하여 저장되어 있는 비밀번호와 대조한다.
//     따라서 회원가입시 비밀번호 항목에 대해서 암호화를 진행해야 한다.
//     시큐리티는 암호화를 위해 BcryptPasswordEncoder 제공하고 권장 해당 클래스를 return 하는 method 생성 후 @Bean 등록
    @Bean
    public PasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();

        hierarchy.setHierarchy("ADMIN > MANAGER > USER");

        return hierarchy;
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//
//        UserDetails user1 = User.builder()
//                .username("admin")
//                .password(bCryptPasswordEncoder().encode("qwer"))
//                .roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(user1);
//    }
}
