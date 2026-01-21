package com.traineeship.module_6_easy.repository;

import com.traineeship.module_6_easy.model.entity.Author;
import com.traineeship.module_6_easy.model.entity.Book;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface BookRepository extends JpaRepository<Book, Long> {

    List<Book> findByAuthor(Author author);

    Optional<Book> findByTitleAndAuthor(String title, Author author);

    @Query("SELECT b FROM Book b JOIN FETCH b.author")
    List<Book> findAllWithAuthors();

    @Query("SELECT b FROM Book b " +
            "WHERE LOWER(b.title) LIKE LOWER(CONCAT('%', :searchText, '%')) " +
            "ORDER BY b.publicationYear DESC")
    List<Book> findByTitleContainingIgnoreCaseOrderByPublicationYearDesc(@Param("searchText") String searchText);

}
