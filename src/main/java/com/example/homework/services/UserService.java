package com.example.homework.services;

import com.example.homework.enums.Role;
import com.example.homework.models.User;
import com.example.homework.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    public boolean createUser(User user){
        String email = user.getEmail();
        if (userRepository.findByEmail(email) != null) return false;
        user.setActive(true);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.getRoles().add(Role.ROLE_USER);
        log.info("Saving new User with email: {}", email);
        userRepository.save(user);
        return true;
    }

    public List<User> list(){
        return userRepository.findAll();
    }

    public void banUser(Principal currentUser, Long id) {
        User user = userRepository.findById(id).orElse(null);
        User user2 =getUserByPrincipal(currentUser);
        if (user != null && !user2.equals(user)) {
            if (user2.getRoles().contains(Role.ROLE_ADMIN)) {
                if (user.isActive()) {
                    user.setActive(false);
                    log.info("Ban User with id = {}; email: {}", user.getId(), user.getEmail());
                } else {
                    user.setActive(true);
                    log.info("Unban User with id = {}; email: {}", user.getId(), user.getEmail());
                }
            userRepository.save(user);
        } else {
                log.warn("User with id = {} attempted to ban another user without admin privileges", user2.getId());
            }
        }else {
            log.warn("User with id = {} attempted to ban themselves or user not found", user2.getId());
        }
    }

    public void changeUserRoles(User user, Map<String, String> form) {
        Set<String> roles = Arrays.stream(Role.values())
                .map(Role::name)
                .collect(Collectors.toSet());
        user.getRoles().clear();
        for(String key : form.keySet()){
            if (roles.contains(key)){
                user.getRoles().add(Role.valueOf(key));
            }
        }
        userRepository.save(user);
    }
    public User getUserByPrincipal(Principal principal) {
        if (principal == null) return new User();
        return userRepository.findByEmail(principal.getName());
    }
}
