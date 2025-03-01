package com.jsonwebtoken.config.security.jwtSecurity;

import org.springframework.beans.factory.annotation.Value;

public class JwtProperties {
    @Value("${jwt.secret}")
    public static String SECRET;
    @Value("${jwt.expiration}")
    public static int EXPIRATION_TIME;
    @Value("${jwt.tokenPrefix}")
    public static String TOKEN_PREFIX;
    @Value("${jwt.headerString}")
    public static String HEADER_STRING;
}