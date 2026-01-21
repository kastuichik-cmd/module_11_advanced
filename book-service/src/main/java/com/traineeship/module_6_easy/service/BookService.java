package com.traineeship.module_6_easy.service;


import com.traineeship.module_6_easy.exceptions.BookNotFoundException;
import com.traineeship.module_6_easy.feign.NotificationClient;
import com.traineeship.module_6_easy.mapper.BookMapper;
import com.traineeship.module_6_easy.model.dto.CreateBookDto;
import com.traineeship.module_6_easy.model.entity.Author;
import com.traineeship.module_6_easy.model.entity.Book;
import com.traineeship.module_6_easy.model.dto.BookDto;
import com.traineeship.module_6_easy.repository.AuthorRepository;
import com.traineeship.module_6_easy.repository.BookRepository;
import jakarta.transaction.Transactional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Optional;

@Slf4j
@Service
public class BookService {

    private final BookRepository bookRepository;
    private final BookMapper bookMapper;
    private final AuthorRepository authorRepository;
    private final NotificationClient notificationClient;

    public BookService(BookRepository bookRepository,
                       BookMapper bookMapper,
                       AuthorRepository authorRepository,
                       NotificationClient notificationClient) {
        this.bookRepository = bookRepository;
        this.bookMapper = bookMapper;
        this.authorRepository = authorRepository;
        this.notificationClient = notificationClient;
    }

    public Page<Book> getBooks(Pageable pageable) {
        return bookRepository.findAll(pageable);
    }

    public Book getBookById(Long id) {
        return bookRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Book not found: " + id));
    }

    public void deleteBookById(Long id) {
        if (!bookRepository.existsById(id)) {
            throw new RuntimeException("Book not found: " + id);
        }
        bookRepository.deleteById(id);
    }

    public void printBooksAuthors() {
        List<Book> books = bookRepository.findAllWithAuthors();
        for (Book book : books) {
            System.out.println(book.getTitle() + " - " + book.getAuthor().getName());
        }
    }

    public List<Book> getBooksByAuthor(String authorName) {
        Author author = getAuthorByName(authorName);
        return bookRepository.findByAuthor(author);
    }

    public Optional<Book> getBookByTitleAndAuthor(String title, String authorName) {
        Author author = getAuthorByName(authorName);
        return bookRepository.findByTitleAndAuthor(title, author);
    }

    public Book createBook(CreateBookDto createBookDto) {
        Author author = getOrCreateAuthor(createBookDto.getAuthor());
        Book book = bookMapper.mapToBookFromCreateDto(createBookDto, author);

        Book savedBook = bookRepository.save(book);

        try {
            notificationClient.notifyService();
        } catch (Exception e) {
            log.error("Не удалось отправить уведомление в NotificationService", e);
        }
        return savedBook;
    }

    public Book updateBook(Long id, BookDto bookDto) {
        Book book = getBookById(id);
        Author author = getOrCreateAuthor(bookDto.getAuthor());
        bookMapper.updateBookFromBookDto(bookDto, author, book);

        return bookRepository.save(book);
    }

    public List<Book> searchBooksByTitle(String searchText) {
        return bookRepository.findByTitleContainingIgnoreCaseOrderByPublicationYearDesc(searchText);
    }

    @Transactional
    public Book createBookWithAuthor(BookDto bookDto, boolean throwError) {
        Author author = new Author();
        author.setName(bookDto.getAuthor());
        authorRepository.save(author);

        Book book = bookMapper.mapToBookFromBookDto(bookDto, author);

        if (throwError) {
            throw new RuntimeException("Ошибка после сохранения автора!");
        }

        return bookRepository.save(book);
    }

    private Author getAuthorByName(String authorName) {
        return authorRepository.findByNameIgnoreCase(authorName)
                .orElseThrow(() ->
                        new BookNotFoundException("Author not found: " + authorName)
                );
    }

    private Author getOrCreateAuthor(String authorName) {
        return authorRepository.findByNameIgnoreCase(authorName)
                .orElseGet(() -> {
                    Author author = new Author();
                    author.setName(authorName);
                    return authorRepository.save(author);
                });
    }
}
