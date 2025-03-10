package com.astroverse.backend.service;

import com.astroverse.backend.model.Post;
import com.astroverse.backend.model.Space;
import com.astroverse.backend.repository.PostRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class PostService {
    private final PostRepository postRepository;

    public PostService(PostRepository postRepository) {
        this.postRepository = postRepository;
    }

    public Post savePost(Post post) {
        return postRepository.save(post);
    }

    public int saveImage(long id, String file) {
        return postRepository.updateImageById(id, file);
    }

    public Post getPost(long id) {
        return postRepository.findById(id);
    }

    public boolean isCreationUser(long idUtente, long idPost) {
        return postRepository.existsByUserIdAndId(idUtente, idPost);
    }

    public int getNumberOfPosts(Space space) {
        return postRepository.countBySpaceId(space.getId());
    }

    public Page<Post> getAllPosts(int limit, int offset) {
        Pageable pageable = PageRequest.of(offset, limit);
        return postRepository.findAll(pageable);
    }

    public long getNumberOfAllPosts() {
        return postRepository.count();
    }
}