package kr.co.farmstory.controller.admin;

import kr.co.farmstory.dto.ProductDTO;
import kr.co.farmstory.entity.Product;
import kr.co.farmstory.service.admin.ProductService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Log4j2
@Controller
@RequiredArgsConstructor
@RequestMapping("/admin")
public class AdminController {

    private final ProductService service;

    @GetMapping("/product/list")
    public String list(Model model) {
        List<ProductDTO> productDTOList = service.prodFindAll();
        model.addAttribute("productDTOList", productDTOList);
        return "/admin/product/list";
    }

    @GetMapping(value = {"/index", "/"})
    public String index() {
        return "/admin/index";
    }

    @GetMapping("/product/register")
    public String registerFrom() {
        return "/admin/product/register";
    }

    @PostMapping("/product/register")
    public String register(ProductDTO productDTO) {
        service.save(productDTO);
        return "redirect:/admin/product/list";
    }
}
