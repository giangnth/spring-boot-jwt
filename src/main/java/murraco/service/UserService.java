package murraco.service;

import javax.servlet.http.HttpServletRequest;

import murraco.dto.RefreshTokenDTO;
import murraco.dto.TokenDTO;
import murraco.dto.UserSignInDTO;
import murraco.model.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import murraco.exception.CustomException;
import murraco.model.User;
import murraco.repository.UserRepository;
import murraco.security.JwtTokenProvider;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private AuthenticationManager authenticationManager;

    public TokenDTO signin(UserSignInDTO user) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
            List<Role> roles = userRepository.findByUsername(user.getUsername()).getRoles();
            String accessToken = jwtTokenProvider.createToken(user.getUsername(), roles);
            String refreshToken = jwtTokenProvider.createRefresh(user.getUsername(), roles);
            return new TokenDTO(accessToken, refreshToken);
        } catch (AuthenticationException e) {
            throw new CustomException("Invalid username/password supplied", HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    public TokenDTO signup(User user) {
        if (!userRepository.existsByUsername(user.getUsername())) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            List<Role> roles = new ArrayList<>();
            roles.add(Role.ROLE_CLIENT);
            user.setRoles(roles);
            userRepository.save(user);
            String accessToken = jwtTokenProvider.createToken(user.getUsername(), user.getRoles());
            String refreshToken = jwtTokenProvider.createRefresh(user.getUsername(), user.getRoles());
            return new TokenDTO(accessToken, refreshToken);
        } else {
            throw new CustomException("Username is already in use", HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    public void delete(String username) {
        userRepository.deleteByUsername(username);
    }

    public User search(String username) {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new CustomException("The user doesn't exist", HttpStatus.NOT_FOUND);
        }
        return user;
    }

    public User whoami(HttpServletRequest req) {
        return userRepository.findByUsername(jwtTokenProvider.getUsername(jwtTokenProvider.resolveTokenInHeader(req)));
    }

    public TokenDTO refresh(RefreshTokenDTO refreshToken) {
        String username = jwtTokenProvider.getUsername(refreshToken.getRefreshToken());
        String accessToken = jwtTokenProvider.createToken(username, userRepository.findByUsername(username).getRoles());
        return new TokenDTO(accessToken, refreshToken.getRefreshToken());
    }

}
