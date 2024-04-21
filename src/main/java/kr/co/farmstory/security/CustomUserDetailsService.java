package kr.co.farmstory.security;

import kr.co.farmstory.entity.User;
import kr.co.farmstory.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<User> findUserUid = userRepository.findById(username);
        UserDetails customUserDetails = null;

        if (findUserUid.isPresent()) {
            //해당하는 사용자가 존재하면 인증 객체 생성
            User user = findUserUid.get();
            customUserDetails = CustomUserDetails.builder()
                    .user(user)
                    .build();
        }
            //SecurityContextHolder 저장
            //사용자가 로그인을 진행한 뒤 사용자 정보는 SecurityContentHolder에 의해서 서버 세션에 관리된다.
            return customUserDetails;
    }
}
