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
public class TermsDTO {
    private String terms;
    private String privacy;
    private String sms;

}
