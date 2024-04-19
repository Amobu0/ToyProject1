package kr.co.farmstory.controller.community;

import kr.co.farmstory.service.community.CommunityService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
@RequiredArgsConstructor
public class CommunityController {

    private final CommunityService communityService;
    
    //관리자만 작성가능
    @GetMapping("/community/notice")
    public String notice(){

        return "/community/notice";
    }

    @GetMapping("/community/menu")
    public String menu(){


        return "/community/menu";
    }

    @GetMapping("/community/chef")
    public String chef(){
        return "/community/chef";
    }

    @GetMapping("/community/qna")
    public String qna(){
        return "/community/qna";
    }

    @GetMapping("/community/faq")
    public String fna(){
        return "/community/faq";
    }



}
