package kr.co.farmstory.dto;
import lombok.*;

/**
 * 24/4/2수정
 */
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class OrderItemsDTO {
    private int itemNo;
    private String orderNo;
    private int prodNo;
    private int itemPrice;
    private int itemDiscount;
    private int Count;
}
