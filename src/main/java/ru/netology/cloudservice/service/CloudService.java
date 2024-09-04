package ru.netology.cloudservice.service;

import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import ru.netology.cloudservice.dao.UserEntity;
import ru.netology.cloudservice.dao.FileEntity;
import ru.netology.cloudservice.exceptions.InvalidCredentialsException;
import ru.netology.cloudservice.exceptions.NotAuthenticatedException;
import ru.netology.cloudservice.file.CustomMultipartFile;
import ru.netology.cloudservice.repository.UserRepository;
import ru.netology.cloudservice.repository.FileRepository;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@AllArgsConstructor
public class CloudService {
    private final FileRepository fileRepository;
    private final UserRepository userRepository;

    @Autowired
    UserDetailsService userDetailsService;

    public ConcurrentHashMap<String, String> login(ConcurrentHashMap<String, Object> credentials) throws JSONException {
        ConcurrentHashMap<String, String> result = new ConcurrentHashMap();
        String authToken;

        UserEntity authEntity = userRepository.findByLogin(credentials.get("login").toString());
        if (authEntity != null) {
            if (authEntity.getPassword().equals(credentials.get("password").toString())) {
                authToken = Instant.now().toEpochMilli() + "-" + UUID.randomUUID();

                authEntity.setToken(authToken);
                userRepository.save(authEntity);

                result.put("auth-token", authToken);
                return result;
            } else {
                throw new InvalidCredentialsException("Invalid credentials!");
            }
        } else {
            throw new InvalidCredentialsException("Invalid credentials!");
        }
    }

    public void logout(String token) {
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity.getToken() != null) {
            authEntity.setToken(null);
            userRepository.save(authEntity);
        } else {
            throw new NotAuthenticatedException("Not authenticated");
        }
    }

    public List<FileEntity> list(String token, Integer limit) {
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            if (limit == null) {
                return fileRepository.findFilesById(authEntity.getUsername());
            } else {
                return fileRepository.findFilesById(authEntity.getUsername(), limit);
            }
        } else {
            throw new NotAuthenticatedException("Not authenticated");
        }
    }

    public MultipartFile getFile(String token, String fileName) {
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            FileEntity file = fileRepository.findFileByName(authEntity.getUsername(), fileName);
            byte[] fileBytes = file.getFile();
            return new CustomMultipartFile(fileName, file.getContentType() , fileBytes);
        } else {
            throw new NotAuthenticatedException("Not authenticated");
        }
    }

    public void postFile(String token, String fileName, MultipartFile file) {
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            if (fileRepository.findFileByName(authEntity.getUsername(), fileName) == null) {
                try {
                    byte[] content = file.getBytes();
                    fileRepository.save(new FileEntity(userRepository.findByToken(token), fileName, content, file.getContentType()));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } else {
            throw new NotAuthenticatedException("Not authenticated");
        }
    }

    public void deleteFile(String token, String fileName) {
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            fileRepository.deleteFileByName(authEntity.getUsername(), fileName);
        } else {
            throw new NotAuthenticatedException("Not authenticated");
        }
    }

    public void putFile(String token, String fileName) {
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            FileEntity file = fileRepository.findFileByName(authEntity.getUsername(), fileName);
            file.setFileName(fileName);
            fileRepository.save(file);
        }
    }
}
