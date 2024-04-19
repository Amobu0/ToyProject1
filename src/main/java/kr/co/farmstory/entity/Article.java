package kr.co.farmstory.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.List;

@Builder
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "article")
public class Article {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int no;

    @Builder.Default
    private int parent = 0;

    @Builder.Default
    private int comment = 0;
    private String cate;
    private String title;
    private String content;

    @Builder.Default
    private int file = 0;

    @Builder.Default
    private int hit = 0;
    private String writer;
    private String regip;

    @CreationTimestamp
    private LocalDateTime rdate;

    private String nick;

    @OneToMany(mappedBy = "ano")
    private List<File> fileList;

}