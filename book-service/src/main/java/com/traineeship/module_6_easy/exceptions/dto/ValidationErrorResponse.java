package com.traineeship.module_6_easy.exceptions.dto;

import java.util.List;

public record ValidationErrorResponse(List<Violation> errors) {
}
