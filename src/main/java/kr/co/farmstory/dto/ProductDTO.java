package kr.co.farmstory.dto;

import kr.co.farmstory.entity.Product;
import lombok.*;
import org.springframework.web.multipart.MultipartFile;

/**
 * 24/4/2수정
 */
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ProductDTO {
    private Long prodNo;
    private String cate;
    private String prodName;
    private Integer prodStock;
    private Integer prodPrice;
    private Integer prodSold;
    private Integer prodDiscount;
    private MultipartFile image1;
    private MultipartFile image2;
    private MultipartFile image3;
    private Integer delivery;
    private String etc;
    private Integer point;
    private String createDate;

    public Product toEntity() {
        return Product.builder()
                .prodName(prodName)
                .cate(cate)
                .prodPrice(prodPrice)
                .point(point)
                .prodDiscount(prodDiscount)
                .delivery(delivery)
                .prodStock(prodStock)
                .etc(etc)
                .build();
    }
}
