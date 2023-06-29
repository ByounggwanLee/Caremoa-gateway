package com.caremoa.gateway;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * @packageName : com.caremoa.gateway
 * @fileName : JwtAuthenticationGatewayFilterFactory.java
 * @author : 이병관
 * @date : 2023.06.11
 * @description : ===========================================================
 *              DATE AUTHOR NOTE
 *              -----------------------------------------------------------
 *              2023.06.11 이병관 최초 생성
 */
@Component
@Slf4j
public class JwtAuthenticationGatewayFilterFactory
		extends AbstractGatewayFilterFactory<JwtAuthenticationGatewayFilterFactory.Config> {

	private final TokenProvider tokenProvider;

	public JwtAuthenticationGatewayFilterFactory(TokenProvider tokenProvider) {
		super(Config.class);
		this.tokenProvider = tokenProvider;
	}

	@Override
	public List<String> shortcutFieldOrder() {
		return Collections.singletonList(TokenProvider.AUTHORITIES_KEY);
	}

	@Override
	public GatewayFilter apply(Config config) {
		return (exchange, chain) -> {
			ServerHttpRequest request = exchange.getRequest();
			ServerHttpResponse response = exchange.getResponse();

			if (!containsAuthorization(request)) {
				return onError(response, "missing authorization header", HttpStatus.BAD_REQUEST);
			}

			String token = extractToken(request);

			log.info("token : {}", token);
			if (!tokenProvider.validateToken(token)) {
				return onError(response, "invalid authorization header", HttpStatus.BAD_REQUEST);
			}

			String userId = tokenProvider.getUserId(token);
			String tokenRole = tokenProvider.getAuthentication(token);
			log.info("userid : {}", userId);
			log.info("role : {}", tokenRole);
			if (!hasRole(tokenRole, config.role)) {
				return onError(response, "invalid role", HttpStatus.FORBIDDEN);
			}

			addAuthorizationHeaders(request, userId, tokenRole);

			return chain.filter(exchange);
		};
	}

	private boolean containsAuthorization(ServerHttpRequest request) {
		return request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION);
	}

	private String extractToken(ServerHttpRequest request) {
		String bearerToken = request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION).get(0);
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7);
		}
		return null;
	}

	private boolean hasRole(String tokenrole, String role) {
		if (role != null) {
			return tokenrole.contains(role);
		} else {
			return true;
		}
	}

	private void addAuthorizationHeaders(ServerHttpRequest request, String userId, String tokenRole) {
		request.mutate().header("X-Authorization-Id", userId).header("X-Authorization-Role", tokenRole).build();
	}

	private Mono<Void> onError(ServerHttpResponse response, String message, HttpStatus status) {
		response.setStatusCode(status);
		DataBuffer buffer = response.bufferFactory().wrap(message.getBytes(StandardCharsets.UTF_8));
		return response.writeWith(Mono.just(buffer));
	}

	@Setter
	public static class Config {

		private String role;

	}

}