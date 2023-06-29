package com.caremoa.gateway;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
* @packageName    : com.caremoa.gateway
* @fileName       : AuthorizationHeaderFilter.java
* @author         : 이병관
* @date           : 2023.06.07
* @description    : https://velog.io/@ililil9482/%EC%9D%B8%EC%A6%9D%EA%B3%BC-%EA%B6%8C%ED%95%9C-4-gateway-filter-%EC%84%A4%EC%A0%95
* ===========================================================
* DATE              AUTHOR             NOTE
* -----------------------------------------------------------
* 2023.06.07        이병관       최초 생성
*/
@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    private Environment env;

    //생성시 Config class를 상속받은 Factory로 넘겨줘야해서 lombok을 사용하지 않고 다음과 같이 처리
    public AuthorizationHeaderFilter(Environment env) {
        super(Config.class);
        this.env = env;
    }

    public static class Config{

    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            //header에 HttpHeaders.AUTHORIZATION 값이 존재하는지 확인
            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get(org.springframework.http.HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authorizationHeader.replace("Bearer", "");

            if(!isJwtValid(jwt)){
                return onError(exchange, "JWT Token is not valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        });
    }

    //token이 유효한지 확인
 	private boolean isJwtValid(String jwt) {
        boolean returnValue = true;

        String subject = null;
        try {
            subject = Jwts.parserBuilder().setSigningKey(env.getProperty("token.secret")).build()  //secret key 값을 통해 parse
                    .parseClaimsJws(jwt).getBody()  //token의 내용을 가져옴
                    .getSubject();
        }catch (Exception e){
            returnValue = false;
        }

        if(subject == null || subject.equals("")){
            returnValue = false;
        }
        return returnValue;
    }

    //에러 발생시 에러 값을 response
    //Mono, Flux -> Spring WebFlux 개념 / 데이터 단위 단일=Mono, 복수=Flux
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(err);
        return response.setComplete();  //Mono 데이터 return
    }
}