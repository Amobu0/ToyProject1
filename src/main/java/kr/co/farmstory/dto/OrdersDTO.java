package kr.co.farmstory.dto;

import lombok.*;

import java.sql.Timestamp;
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
public class OrdersDTO {
    private String orderNo;
    private String userId;
    private int orderTotalPrice;
    private String orderAddr;
    private int orderStatus;
    private LocalDateTime orderDate;
    private int itemDiscount;

}
