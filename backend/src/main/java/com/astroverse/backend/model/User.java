package com.astroverse.backend.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Entity
@AllArgsConstructor
@Getter
@Setter
@Table(name = "user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private boolean isAdmin;
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private Set<UserSpace> userSpaces = new HashSet<>();
    protected String nome;
    protected String cognome;
    @Column(unique = true, nullable = false)
    protected String username;
    @Column(unique = true, nullable = false)
    protected String email;
    protected String password;

    public User() {
        isAdmin = false;
    }

    public User(boolean isAdmin) {
        this.isAdmin = isAdmin;
    }

    //TODO
}