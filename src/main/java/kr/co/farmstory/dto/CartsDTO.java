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
public class CartsDTO {
    private int cartNO;
    private String userID;
    private int prodNo;
    private int cartProdCount;
    private LocalDateTime cartProdDate;
}
