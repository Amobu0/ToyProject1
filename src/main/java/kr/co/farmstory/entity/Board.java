package kr.co.farmstory.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "Board")
public class Board {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int no;


    private String uid;

    private int parent = 0;

    private int comment = 0;
    private String cate;
    private String title;
    private String content;

    private int file = 0;

    private int hit = 0;


    private String regip;

    @CreationTimestamp
    private LocalDateTime rdate;




}
