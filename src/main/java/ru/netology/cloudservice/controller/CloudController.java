package ru.netology.cloudservice.controller;

import lombok.AllArgsConstructor;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.netology.cloudservice.dao.UserEntity;
import ru.netology.cloudservice.exceptions.InvalidCredentialsException;
import ru.netology.cloudservice.exceptions.NotAuthenticatedException;
import ru.netology.cloudservice.jsonobjects.Credentials;
import ru.netology.cloudservice.dao.FileEntity;
import ru.netology.cloudservice.jsonobjects.FileList;
import ru.netology.cloudservice.logger.CloudLogger;
import ru.netology.cloudservice.logger.CloudLoggerImpl;
import ru.netology.cloudservice.logger.LogType;
import ru.netology.cloudservice.repository.UserRepository;
import ru.netology.cloudservice.service.CloudService;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/")
@AllArgsConstructor
public class CloudController {
    private final CloudService service;
    private final CloudLogger logger = new CloudLoggerImpl();
    private final UserRepository userRepository;
    private final String BEARER_PREFIX = "Bearer ";


    @PostMapping("login")
    public ConcurrentHashMap<String, String> login(@RequestBody Credentials credentials) throws IOException, JSONException {
        UserEntity authEntity = userRepository.findByLogin(credentials.getLogin());
        if (authEntity != null) {
            return service.login(credentials, authEntity);
        } else {
            logger.log("User " + credentials.getLogin() + " login failed.", LogType.ERROR, true);
            throw new InvalidCredentialsException("Invalid credentials.");
        }
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @PostMapping("logout")
    public void logout(@RequestHeader(name = "auth-token") String token) throws IOException {
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity.getToken() != null) {
            service.logout(token, authEntity);
        } else {
            logger.log("User not authenticated.", LogType.ERROR, true);
            throw new NotAuthenticatedException("Not authenticated.");
        }
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @GetMapping("list")
    public List<FileList> list(@RequestHeader(name = "auth-token") String token,
                               @RequestParam("limit") Integer limit) throws IOException {
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            return service.list(token, limit, authEntity);
        } else {
            logger.log("User not authenticated.", LogType.ERROR, true);
            throw new NotAuthenticatedException("Not authenticated.");
        }
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @PostMapping("file")
    public void postFile(@RequestHeader(name = "auth-token") String token,
                           @RequestParam("filename") String fileName,
                           @RequestBody MultipartFile file) throws IOException {
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
                service.postFile(token, fileName, file, authEntity);
        } else {
            logger.log("User not authenticated.", LogType.ERROR, true);
            throw new NotAuthenticatedException("Not authenticated.");
        }
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @DeleteMapping("file")
    public void deleteFile(@RequestHeader(name = "auth-token") String token,
                             @RequestParam("filename") String fileName) throws IOException {
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            service.deleteFile(token, fileName, authEntity);
        } else {
            logger.log("User not authenticated.", LogType.ERROR, true);
            throw new NotAuthenticatedException("Not authenticated.");
        }
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @PutMapping("file")
    public void putFile(@RequestHeader(name = "auth-token") String token,
                          @RequestParam("filename") String fileName) throws IOException {
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            service.putFile(token, fileName, authEntity);
        } else {
            logger.log("User not authenticated.", LogType.ERROR, true);
            throw new NotAuthenticatedException("Not authenticated.");
        }
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @GetMapping("file")
    public byte[] getFile(@RequestHeader(name = "auth-token") String token,
                        @RequestParam("filename") String fileName) throws IOException {
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            return service.getFile(token, fileName, authEntity);
        } else {
            logger.log("User not authenticated.", LogType.ERROR, true);
            throw new NotAuthenticatedException("Not authenticated.");
        }
    }

    private String getTokenWithoutPrefix(String token) {
        if (token.startsWith(BEARER_PREFIX)) {
            return token.substring(BEARER_PREFIX.length());
        }
        return token;
    }
}
