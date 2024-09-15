package ru.netology.cloudservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.netology.cloudservice.dao.AuthorityEntity;

import java.util.List;

@Repository
public interface AuthorityRepository extends JpaRepository<AuthorityEntity, Integer> {
    @Query("select a from AuthorityEntity a where a.username = :username")
    List<AuthorityEntity> findAllByUsername(@Param("username") String username);
}
