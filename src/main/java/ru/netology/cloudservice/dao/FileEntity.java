package ru.netology.cloudservice.dao;

import jakarta.persistence.*;
import lombok.*;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
@Table(name = "FILES")
public class FileEntity {
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "username", referencedColumnName = "username")
    private UserEntity user;

    @Id
    @Column(name = "file_name", nullable = false)
    private String fileName;

    @Column(name = "file", nullable = false)
    private byte[] file;

    @Column(name = "file_size", nullable = false)
    private long fileSize;

    @Column(name = "content_type", nullable = false)
    private String contentType;
}
