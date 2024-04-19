package kr.co.farmstory.service.event;

import kr.co.farmstory.entity.Article;
import kr.co.farmstory.repository.article.ArticleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class EventService {

    private final ArticleRepository articleRepository;

    public List<Article> getAllEvents(){
        return articleRepository.findAll();
    }
}