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
@Table(name = "Orders")
public class Orders {

    @Id @GeneratedValue
    @Column(name = "order_id")
    private int id;
    private String uid;
    private String name;
    private String hp;
    private String zip;
    private String addr1;
    private String addr2;
    private String pay;
    private String text;
}
