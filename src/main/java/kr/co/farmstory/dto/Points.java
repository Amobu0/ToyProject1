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
public class Points {
    private int pointNo;
    private String userId;
    private int point;
    private String pointDesc;
    private LocalDateTime pointDate;
}
