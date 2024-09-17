package ru.netology.cloudservice.exceptions;

public class FileCannotBeUploadedException extends RuntimeException {
    public FileCannotBeUploadedException(String message) {
        super(message);
    }
}
