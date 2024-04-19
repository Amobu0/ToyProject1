package kr.co.farmstory.dto;

import java.util.Date;

/**
 *  아이디 비밀번호 이름 닉네임 이메일 휴대폰 (역할) 우편번호 주소 상세주소 ip sms동의여부 포인트 탈퇴시기 회원가입시기
 *   uid / pass / name / nick / email / hp / zip / addr1 / addr2 / regip / sms / point / leaveDate /regDate
 */
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
public class UserDTO {

    private String uid;
    private String pass;
    private String name;
    private String nick;
    private String email;
    private String hp;
    private String role;
    private String zip;
    private String addr1;
    private String addr2;
    private String regIp;
    private String sms;
    private String regDate;
    private String leaveDate;
    private int point;

}
