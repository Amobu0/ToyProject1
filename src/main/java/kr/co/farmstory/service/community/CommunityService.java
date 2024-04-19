package kr.co.farmstory.service.community;

import kr.co.farmstory.repository.article.ArticleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;


@Service
@Slf4j
@RequiredArgsConstructor
public class CommunityService {

    private final ArticleRepository articleRepository;
    private final ModelMapper modelMapper;





}
