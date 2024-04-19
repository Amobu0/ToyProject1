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
public class ConfigDTO {
    private String cate;
    private String admin;
    private String boardName;
    private LocalDateTime createDate;
    private int total;
}
