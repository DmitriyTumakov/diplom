package ru.netology.cloudservice.advice;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import ru.netology.cloudservice.exceptions.FileCannotBeUploadedException;
import ru.netology.cloudservice.exceptions.InvalidCredentialsException;
import ru.netology.cloudservice.exceptions.NotAuthenticatedException;

import java.io.FileNotFoundException;

@RestControllerAdvice
public class ExceptionHandlerAdvice {
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Object> handleInvalidCredentialsException(InvalidCredentialsException e) {
        return new ResponseEntity<>("Invalid Credentials!", HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(FileNotFoundException.class)
    public ResponseEntity<Object> handleFileNotFoundException(FileNotFoundException e) {
        return new ResponseEntity<>("File not found!", HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(NotAuthenticatedException.class)
    public ResponseEntity<Object> handleNotAuthenticatedException(NotAuthenticatedException e) {
        return new ResponseEntity<>("Not authenticated!", HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(FileCannotBeUploadedException.class)
    public ResponseEntity<Object> handleFileCannotBeUploadedException(FileCannotBeUploadedException e) {
        return new ResponseEntity<>("File Cannot be Uploaded!", HttpStatus.BAD_REQUEST);
    }
}
