package com.traineeship.module_6_easy.model.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateBookDto {

    @NotNull(message = "Title не может быть пустым")
    @Size(min = 3, max = 100, message = "Title должен быть от 3 до 100 символов")
    private String title;

    @NotNull(message = "Author не может быть пустым")
    @Size(min = 3, max = 50, message = "Имя автора должно быть от 3 до 50 символов")
    private String author;

    @NotNull(message = "Год публикации обязателен")
    @Min(value = 1800, message = "Год публикации должен быть не меньше 1800")
    private Integer publicationYear;
}
