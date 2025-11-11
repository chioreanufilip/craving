package com.cravingapp.craving.service;


import com.cravingapp.craving.model.User;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import com.cravingapp.craving.repository.UserRepo;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;


@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepo repoUser;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User createUser(User user) {
        String pass = user.getPassword();
        String newPass = passwordEncoder.encode(pass);
        user.setPassword(newPass);
        return repoUser.save(user);
    }
    public Optional<User> findUserByEmail(String email) {
        return repoUser.findByEmail(email);
    }
    public Optional<User> findUserByUsername(String username) {
        return repoUser.findByEmail(username);
    }
    public Optional<User> findUserById(Long id) {
        return repoUser.findById(id.intValue());
    }
    public void deleteUserById(Long id) {
        repoUser.deleteById(id.intValue());
    }
    public List<User> findAll(){
        return repoUser.findAll();
    }
    @Transactional
    public User updateUser(Integer id, User userWithUpdates) {
        Optional<User> existingUserOpt = repoUser.findById(id);

        if (existingUserOpt.isEmpty()) {
            return null;
        }

        User existingUser = existingUserOpt.get();


        existingUser.setPassword(userWithUpdates.getPassword());
        existingUser.setEmail(userWithUpdates.getEmail());
        existingUser.setUsername(userWithUpdates.getUsername());
        existingUser.setBio(userWithUpdates.getBio());
        existingUser.setProfile_picture_url(userWithUpdates.getProfile_picture_url());
        return repoUser.save(existingUser);
    }
}
