package ru.netology.cloudservice.dao;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
@Table(name = "AUTHORITIES")
public class AuthorityEntity implements GrantedAuthority {
    @Id
    private String username;

    @Column
    private String authority;

    @Override
    public String getAuthority() {
        return authority;
    }
}
