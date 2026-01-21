package com.traineeship.module_6_easy.exceptions;

public class BookNotFoundException extends RuntimeException {
    public BookNotFoundException(Long id) {
        super("Книга с id: " + id + " не найдена");
    }
    public BookNotFoundException(String id) {
        super();
    }
}
