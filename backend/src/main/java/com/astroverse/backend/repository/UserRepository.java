package com.astroverse.backend.repository;

import com.astroverse.backend.model.User;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    boolean existsByEmail(String email);
    boolean existsByEmailAndIdNot(String email, Long id);
    boolean existsByUsernameAndIdNot(String username, Long id);
    boolean existsByUsername(String username);
    boolean existsByEmailHash(String emailHash);
    // Per il metodo changeUserData
    boolean existsByEmailHashAndIdNot(String emailHash, Long id);
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.password = :password WHERE u.username = :username")
    int updatePasswordByUsername(String username, String password);
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.nome = :nome, u.cognome = :cognome, u.email = :email, u.username = :username WHERE u.id = :id")
    int updateUserById(@Param("id") long id,
                       @Param("nome") String nome,
                       @Param("cognome") String cognome,
                       @Param("email") String email,
                       @Param("username") String username);
    User findByEmail(String email);
    User getUserById(Long id);
    Optional<User> findByEmailHash(String emailHash);
    // Per la migrazione PQC
    List<User> findByIsQuantumEncryptedFalse();
    @Query("SELECT u.password FROM User u WHERE u.id = :id")
    String findPasswordById(@Param("id") Long id);
}