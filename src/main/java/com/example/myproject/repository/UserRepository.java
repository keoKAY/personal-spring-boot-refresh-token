package com.example.myproject.repository;

import com.example.myproject.document.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.stereotype.Repository;

import java.util.Optional;


public interface     UserRepository extends MongoRepository<User,String> {

   public  Optional<User> findByUsername(String username);
    public boolean existsByUsername(String username);

}
