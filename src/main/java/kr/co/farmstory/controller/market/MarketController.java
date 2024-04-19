package kr.co.farmstory.controller.market;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MarketController {

    @GetMapping("/market/list")
    public String list(){
        return "/market/list";
    }

    @GetMapping("/market/cart")
    public String cart(){
        return "/market/cart";
    }

    @GetMapping("/market/order")
    public String order(){
        return "/market/order";
    }

    @GetMapping("/market/view")
    public String view(){
        return "/market/view";
    }

}
