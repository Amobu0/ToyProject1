package kr.co.farmstory.entity;

import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDateTime;

/**
 * @MappedSuperclass JPA Entity 클래스들이 해당 추상 클래스를 상속할 경우 createDate, modifiedDate를 컬럼으로 인식
 * @EntityListeners(AuditingEntityListener.class 해당 클래스에 Auditing 기능을 포함
 * @CreatedDate Entity가 생성되어 저장될 때 시간이 자동 저장
 * @LastModifiedDate 조회한 Entity의 값을 변경할 때 시간이 자동 저장
 * ****main 메소드가 있는 클래스에 @EnableJpaAuditing 추가하여 활성화시킨다.***
 */
@Getter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseTimeEntity {

    @CreatedDate
    @DateTimeFormat(pattern = "yyyy-MM-dd/HH:mm:ss")
    private LocalDateTime createDate;

    @LastModifiedDate
    @DateTimeFormat(pattern = "yyyy-MM-dd/HH:mm:ss")
    private LocalDateTime modifiedDate;
}
