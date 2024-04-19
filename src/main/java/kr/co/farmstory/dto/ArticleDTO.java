package kr.co.farmstory.dto;


import lombok.*;

import java.time.LocalDateTime;

/**
 * 24/4/2수정
 */
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ArticleDTO {
    private int no;
    private int parent;
    private int comment;
    private String cate;
    private String title;
    private String content;
    private int file;
    private int hit;
    private String writer;
    private String regIp;
    private LocalDateTime rDate;
    private String nick;

}
