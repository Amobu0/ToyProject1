package kr.co.farmstory.oauth2;

import kr.co.farmstory.dto.oauth2.GoogleResponse;
import kr.co.farmstory.dto.oauth2.NaverResponse;
import kr.co.farmstory.dto.oauth2.OAuth2Response;
import kr.co.farmstory.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;


/**
 * session 방식에서 CustomUserDetailsService 에 해당하는 부분이다
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("oAuth2User.getAttributes()={}", oAuth2User.getAttributes());

        //네이버, 구글 어떤 provider 인지 알아보기
        String provider = userRequest.getClientRegistration().getRegistrationId();
        log.info("provider={}", provider);

        OAuth2Response oAuth2Response = null;
        if (provider.equals("naver")) {

            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());

        } else if (provider.equals("google")) {

            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());

        } else {

            return null;
        }

        String role = "USER";

        return new CustomOAuth2User(oAuth2Response, role);
    }
}
