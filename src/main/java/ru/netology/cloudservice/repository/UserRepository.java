package ru.netology.cloudservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.netology.cloudservice.dao.UserEntity;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {
    @Query("select a from UserEntity a where a.username = :login")
    UserEntity findByLogin(@Param("login") String login);

    @Query("select a from UserEntity a where a.token = :token")
    UserEntity findByToken(@Param("token") String token);
}
