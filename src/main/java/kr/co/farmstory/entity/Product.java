package kr.co.farmstory.entity;

import jakarta.persistence.*;
import kr.co.farmstory.dto.ProductDTO;
import lombok.*;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "products")
public class Product extends BaseTimeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long prodNo;
    private String cate;
    private String prodName;
    private Integer prodStock;
    private Integer prodPrice;
    private Integer prodSold;
    private Integer prodDiscount;
    private String image1;
    private String image2;
    private String image3;
    private Integer delivery;
    private String etc;
    private Integer point;

    public ProductDTO toDTO() {
        return ProductDTO.builder()
                .prodName(prodName)
                .cate(cate)
                .prodPrice(prodPrice)
                .prodStock(prodStock)
                .createDate(String.valueOf(getCreateDate()))
                .build();
    }
}
