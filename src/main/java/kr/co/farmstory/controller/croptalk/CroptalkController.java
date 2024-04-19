package kr.co.farmstory.controller.croptalk;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class CroptalkController {

    @GetMapping("/croptalk/grow")
    public String grow(){
        return "/croptalk/grow";
    }

    @GetMapping("/croptalk/school")
    public String school(){
        return "/croptalk/school";
    }

    @GetMapping("/croptalk/story")
    public String story(){
        return "/croptalk/story";
    }
}
