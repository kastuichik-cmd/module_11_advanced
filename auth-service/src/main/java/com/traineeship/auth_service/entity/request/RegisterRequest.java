package com.traineeship.auth_service.entity.request;

public record RegisterRequest(
        String username,
        String password,
        String role
) {}
