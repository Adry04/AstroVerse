package com.astroverse.backend.repository;

import com.astroverse.backend.model.Post;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface PostRepository extends JpaRepository<Post, Long> {
    @Modifying
    @Transactional
    @Query("UPDATE Post p SET p.file = :image WHERE p.id = :id")
    int updateImageById(@Param("id") long id, @Param("image") String image);
    Post findById(long id);
    boolean existsByUserIdAndId(Long userId, Long postId);  //verifica se l'utente ha creato il post
}