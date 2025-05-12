package org.example.expert.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.log4j.Log4j2;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.common.exception.ServerException;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Log4j2(topic = "JwtUtil")
@Component // 스프링 빈으로 등록
public class JwtUtil {

    private static final String BEARER_PREFIX = "Bearer "; // 토큰 앞에 붙는 문자열 ( Authorization 헤더에서 사용 )
    private static final long TOKEN_TIME = 60 * 60 * 1000L; // 토큰 유효 시간 : 60분

    @Value("${jwt.secret.key}") // application.yml 에 설정된 JWT 비밀키 주입
    private String secretKey;
    private Key key; // 실제 암호화에 사용할 키 객체
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256; // 사용할 서명 알고리즘

    @PostConstruct // 의존성 주입이 끝난 후 실행되는 초기화 메서드
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        // base64로 인코딩된 비밀키를 디코딩해서 byte 배열로 변환
        key = Keys.hmacShaKeyFor(bytes);
        // byte 배열 기반으로  ~ 키 생성
    }

    //JWT 토큰 생성 메서드
    public String createToken(Long userId, String email, String nickname, UserRole userRole) {
        Date date = new Date(); // 현재 시간

        return BEARER_PREFIX + // Bearer 접두어 붙이기
                Jwts.builder() // JWT 생성 빌더 시작
                        .setSubject(String.valueOf(userId)) // 사용자의 ID를 문자열로 변환하여  subject 로 설정
                        .claim("email", email) // 클레임에 이메일 정보 추가, 클레임 : payload 내용의 한 덩어리
                        .claim("nickname", nickname) // 추가
                        .claim("userRole", userRole)
                        .setExpiration(new Date(date.getTime() + TOKEN_TIME)) // 만료시간 설정 (현재 + 1시간)
                        .setIssuedAt(date) // 발급일
                        .signWith(key, signatureAlgorithm) // 암호화 알고리즘
                        .compact(); // 최종적으로 문자열 토큰 생성
    }

    // 접두어 제거 메서드
    public String substringToken(String tokenValue) {
        if (StringUtils.hasText(tokenValue) && tokenValue.startsWith(BEARER_PREFIX)) {
            return tokenValue.substring(7); // 접두어를 제외한 나머지 토큰 반환
        }
        throw new ServerException("Not Found Token");
    }

    // 토큰에서 Claims(본문정보) 추출
    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
