package com.cravingapp.craving.model;

import jakarta.persistence.*;
import jdk.jfr.Timestamp;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@NoArgsConstructor
@Data
@Table(name = "\"user\"")
public class User implements UserDetails {
    @Id
    @Column(name = "user_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column
    private String username;
    @Column(name = "password_hash")
    private String password;
    @Column
    private String email;
    @Column
    private String bio;
    @Column
    private String profile_picture_url;
    @Column
    private LocalDateTime created_at;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Aici poți returna roluri, de ex. "ROLE_PARTICIPANT"
        // Pentru simplitate, returnăm o listă goală momentan.
        return List.of();
    }
    @Override
    public String getUsername() {
        return username;
    }
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    @Override
    public boolean isEnabled() {
        return true;
    }
}
