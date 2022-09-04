package com.prgrms.devcourse.user;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    public UserService(PasswordEncoder passwordEncoder, UserRepository userRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public User login(String username, String credentials) {
        User user = userRepository.findByLoginId(username)
                .orElseThrow(() -> new UsernameNotFoundException("Could not found user for " + username));
        user.checkPassword(passwordEncoder, credentials);
        return user;
    }
    @Transactional(readOnly = true)
    public Optional<User> findByLoginId(String loginId) {
        return userRepository.findByLoginId(loginId);
    }

//    @Override
//    @Transactional(readOnly = true)
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        return userRepository.findByLoginId(username)
//                .map(user ->
//                        User.builder()
//                                .username(user.getLoginId())
//                                .password(user.getPasswd())
//                                .authorities(user.getGroup().getAuthorities())
//                                .build()
//                )
//                .orElseThrow(() -> new UsernameNotFoundException("Could not found user for " + username));
//
//    }

}
