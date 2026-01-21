package com.traineeship.module_6_easy.mapper;

import com.traineeship.module_6_easy.model.dto.BookDto;
import com.traineeship.module_6_easy.model.dto.CreateBookDto;
import com.traineeship.module_6_easy.model.entity.Author;
import com.traineeship.module_6_easy.model.entity.Book;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

import static org.mapstruct.MappingConstants.ComponentModel.SPRING;

@Mapper(componentModel = SPRING)
public interface BookMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "author", source = "author")
    Book mapToBookFromCreateDto(CreateBookDto createBookDto, Author author);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "author", source = "author")
    Book mapToBookFromBookDto(BookDto bookDto, Author author);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "author", source = "author")
    void updateBookFromBookDto(BookDto bookDto, Author author, @MappingTarget Book book);
}
