package ru.netology.cloudservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.netology.cloudservice.dao.FileEntity;

import java.util.List;

@Repository
public interface FileRepository extends JpaRepository<FileEntity,Long> {
    @Query("select f from FileEntity f where f.user.username = :username order by f.user.token")
    List<FileEntity> findFilesById(@Param("username") String id);

    @Query("select f from FileEntity f where f.user.username = :username order by f.user.token limit :limit")
    List<FileEntity> findFilesById(@Param("username") String id, @Param("limit") int limit);

    @Query("select f from FileEntity f where f.user.username = :username and f.fileName = :file_name")
    FileEntity findFileByName(@Param("username") String id, @Param("file_name") String fileName);

    @Query("delete from FileEntity f where f.user.username = :username and f.fileName = :file_name")
    void deleteFileByName(@Param("username") String username, @Param("file_name") String fileName);
}
