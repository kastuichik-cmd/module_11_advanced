package com.traineeship.module_6_easy.controller;

import com.traineeship.module_6_easy.exceptions.BookNotFoundException;
import com.traineeship.module_6_easy.model.dto.CreateBookDto;
import com.traineeship.module_6_easy.model.entity.Book;
import com.traineeship.module_6_easy.model.dto.BookDto;
import com.traineeship.module_6_easy.service.BookService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/books")
@Slf4j
@RequiredArgsConstructor
public class BookController {
    private final BookService bookService;

    @GetMapping
    public ResponseEntity<Page<Book>> getBooks(Pageable pageable) {
        return ResponseEntity.ok(bookService.getBooks(pageable));
    }

    @GetMapping("/{id}")
    public Book getBook(@PathVariable Long id) {
        return bookService.getBookById(id);
    }

    @GetMapping("/author/{authorName}")
    public List<Book> getBooksByAuthor(@PathVariable String authorName) {
        return bookService.getBooksByAuthor(authorName);
    }

    @GetMapping("/search/author-title")
    public ResponseEntity<Book> getBookByTitleAndAuthor(
            @RequestParam String title,
            @RequestParam String author) {
        return bookService.getBookByTitleAndAuthor(title, author)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<Book> createBook(@RequestBody @Valid CreateBookDto createBookDto) {
        Book book = bookService.createBook(createBookDto);
        log.info("Получили объект: {} - {}", book.getId(), book.getTitle());

        return ResponseEntity.status(HttpStatus.CREATED).body(book);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Book> updateBook(@PathVariable Long id,
                                           @RequestBody BookDto bookDto) {
        if (bookDto == null) throw new BookNotFoundException(id);

        return ResponseEntity.ok(bookService.updateBook(id, bookDto));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteBook(@PathVariable Long id) {
        bookService.deleteBookById(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/n1")
    public void n1Test() {
        bookService.printBooksAuthors();
    }

    @GetMapping("/search-by-title")
    public List<Book> searchBooks(@RequestParam String title) {
        return bookService.searchBooksByTitle(title);
    }

    @PostMapping("/create-with-author")
    public Book createBookWithAuthor(@RequestBody BookDto bookDto, @RequestParam boolean throwError) {
        return bookService.createBookWithAuthor(bookDto, throwError);
    }
}
