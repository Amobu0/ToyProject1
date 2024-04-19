package kr.co.farmstory.controller.event;

import kr.co.farmstory.entity.Article;
import kr.co.farmstory.service.event.EventService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequiredArgsConstructor
@RequestMapping("/event")
public class EventController {

    private final EventService eventService;
    @GetMapping("/event")
    public String eventPage(Model model) {
        // 서비스를 통해 이벤트 목록을 가져옴
        List<Article> events = eventService.getAllEvents();
        // 모델에 이벤트 목록을 추가하여 템플릿에 전달
        model.addAttribute("posts", events);
        return "/event/event";
    }
}