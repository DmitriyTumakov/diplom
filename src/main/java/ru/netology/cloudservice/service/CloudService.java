package ru.netology.cloudservice.service;

import lombok.AllArgsConstructor;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import ru.netology.cloudservice.jsonobjects.Credentials;
import ru.netology.cloudservice.dao.UserEntity;
import ru.netology.cloudservice.dao.FileEntity;
import ru.netology.cloudservice.exceptions.InvalidCredentialsException;
import ru.netology.cloudservice.exceptions.NotAuthenticatedException;
import ru.netology.cloudservice.jsonobjects.FileList;
import ru.netology.cloudservice.repository.UserRepository;
import ru.netology.cloudservice.repository.FileRepository;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static ru.netology.cloudservice.security.SecurityConfig.encoder;

@Service
@AllArgsConstructor
public class CloudService {
    private final FileRepository fileRepository;
    private final UserRepository userRepository;
    private final String BEARER_PREFIX = "Bearer ";

    @Autowired
    UserDetailsService userDetailsService;

    public ConcurrentHashMap<String, String> login(Credentials credentials) throws JSONException {
        ConcurrentHashMap<String, String> result = new ConcurrentHashMap();
        String authToken;

        UserEntity authEntity = userRepository.findByLogin(credentials.getLogin());
        if (authEntity != null) {
            if (encoder().matches(credentials.getPassword(), authEntity.getPassword())) {
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
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity.getToken() != null) {
            authEntity.setToken(null);
            userRepository.save(authEntity);
        } else {
            throw new NotAuthenticatedException("Not authenticated");
        }
    }

    public List<FileList> list(String token, Integer limit) {
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            List<FileList> fileList = new ArrayList<>();
            List<FileEntity> fileEntities = fileRepository.findFilesById(authEntity.getUsername());
            for (FileEntity fileEntity : fileEntities) {
                fileList.add(new FileList(fileEntity.getFileName(), fileEntity.getFileSize()));
            }
            
            return fileList;
        } else {
            throw new NotAuthenticatedException("Not authenticated");
        }
    }

    public byte[] getFile(String token, String fileName) throws IOException {
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            FileEntity fileEntity = fileRepository.findFileByName(authEntity.getUsername(), fileName);

            File file = new File("tmp/" + fileName + ".tmp");
            FileUtils.writeByteArrayToFile(file, fileEntity.getFile());
            return fileEntity.getFile();
        } else {
            throw new NotAuthenticatedException("Not authenticated");
        }
    }

    public void postFile(String token, String fileName, MultipartFile file) {
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            if (fileRepository.findFileByName(authEntity.getUsername(), fileName) == null) {
                try {
                    FileEntity fileEntity = new FileEntity();
                    fileEntity.setUser(authEntity);
                    fileEntity.setFileName(fileName);
                    fileEntity.setFile(file.getInputStream().readAllBytes());
                    fileEntity.setFileSize(file.getBytes().length);
                    fileEntity.setContentType(file.getContentType());
                    fileRepository.save(fileEntity);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } else {
            throw new NotAuthenticatedException("Not authenticated");
        }
    }

    public void deleteFile(String token, String fileName) {
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            fileRepository.delete(fileRepository.findFileByName(authEntity.getUsername(), fileName));
        } else {
            throw new NotAuthenticatedException("Not authenticated");
        }
    }

    public void putFile(String token, String fileName) {
        token = getTokenWithoutPrefix(token);
        UserEntity authEntity = userRepository.findByToken(token);
        if (authEntity != null) {
            FileEntity file = fileRepository.findFileByName(authEntity.getUsername(), fileName);
            file.setFileName(fileName);
            fileRepository.save(file);
        }
    }

    public String getTokenWithoutPrefix(String token) {
        if (token.startsWith(BEARER_PREFIX)) {
            return token.substring(BEARER_PREFIX.length());
        }
        return token;
    }
}
