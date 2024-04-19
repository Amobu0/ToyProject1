package kr.co.farmstory.entity;

import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "OrderItem")
public class OrderItem {

    @Id @GeneratedValue
    @Column(name = "order_item_id")
    private int id;

}
