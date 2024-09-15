package ru.netology.cloudservice.jsonobjects;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class FileList {
    private String filename;
    private long size;
}
