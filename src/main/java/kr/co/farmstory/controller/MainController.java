package kr.co.farmstory.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class MainController {


    /**
     * 1. client 요청
     * 2. Servlet Container 는 여러개의 필터를 가지고 있고 요청은 필터를 통과해서 들어온다
     * 3. Spring Security 를 의존성으로 추가해 놓게 되면 Filter 에서 해당 요청을 가로챈다.
     *
     *
     */
    @GetMapping(value = {"/", "/index"})
    public String index(){
        return "/index";
    }

}
