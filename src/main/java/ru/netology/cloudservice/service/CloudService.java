package ru.netology.cloudservice.service;

import lombok.AllArgsConstructor;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import ru.netology.cloudservice.exceptions.FileCannotBeUploadedException;
import ru.netology.cloudservice.jsonobjects.Credentials;
import ru.netology.cloudservice.dao.UserEntity;
import ru.netology.cloudservice.dao.FileEntity;
import ru.netology.cloudservice.exceptions.InvalidCredentialsException;
import ru.netology.cloudservice.jsonobjects.FileList;
import ru.netology.cloudservice.logger.CloudLogger;
import ru.netology.cloudservice.logger.CloudLoggerImpl;
import ru.netology.cloudservice.logger.LogType;
import ru.netology.cloudservice.repository.UserRepository;
import ru.netology.cloudservice.repository.FileRepository;

import java.io.*;
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
    private final CloudLogger logger = new CloudLoggerImpl();

    @Autowired
    UserDetailsService userDetailsService;

    public ConcurrentHashMap<String, String> login(Credentials credentials, UserEntity authEntity) throws JSONException, IOException {
        if (credentials.getLogin().equals(authEntity.getUsername())) {
            if (encoder().matches(credentials.getPassword(), authEntity.getPassword())) {
                ConcurrentHashMap<String, String> result = new ConcurrentHashMap();
                String authToken;

                authToken = Instant.now().toEpochMilli() + "-" + UUID.randomUUID();

                authEntity.setToken(authToken);
                userRepository.save(authEntity);

                logger.log("User " + credentials.getLogin() + " login succeeded.", LogType.INFO, true);

                result.put("auth-token", authToken);
                return result;
            } else {
                logger.log("User " + credentials.getLogin() + " login failed.", LogType.ERROR, true);
                throw new InvalidCredentialsException("Invalid credentials.");
            }
        } else {
            logger.log("User " + credentials.getLogin() + " login failed.", LogType.ERROR, true);
            throw new InvalidCredentialsException("Invalid credentials.");
        }
    }

    public void logout(String token, UserEntity authEntity) throws IOException {
        authEntity.setToken(null);
        userRepository.save(authEntity);

        logger.log("User " + authEntity.getUsername() + " logout succeeded.", LogType.INFO, true);
    }

    public List<FileList> list(String token, Integer limit, UserEntity authEntity) throws IOException {
        List<FileList> fileList = new ArrayList<>();
        List<FileEntity> fileEntities = fileRepository.findFilesById(authEntity.getUsername());
        for (FileEntity fileEntity : fileEntities) {
            fileList.add(new FileList(fileEntity.getFileName(), fileEntity.getFileSize()));
        }

        return fileList;
    }

    public byte[] getFile(String token, String fileName, UserEntity authEntity) throws IOException {
        FileEntity fileEntity = fileRepository.findFileByName(authEntity.getUsername(), fileName);

        File file = new File("tmp/" + fileName + ".tmp");
        FileUtils.writeByteArrayToFile(file, fileEntity.getFile());

        logger.log("User " + authEntity.getUsername() + " downloaded file " + fileName + '.', LogType.INFO, true);
        return fileEntity.getFile();
    }

    public void postFile(String token, String fileName, MultipartFile file, UserEntity authEntity) throws IOException {
        if (fileRepository.findFileByName(authEntity.getUsername(), fileName) == null) {
            try {
                FileEntity fileEntity = new FileEntity();
                fileEntity.setUser(authEntity);
                fileEntity.setFileName(fileName);
                fileEntity.setFile(file.getInputStream().readAllBytes());
                fileEntity.setFileSize(file.getBytes().length);
                fileEntity.setContentType(file.getContentType());
                fileRepository.save(fileEntity);

                logger.log("User " + authEntity.getUsername() + " post file " + fileName + '.', LogType.INFO, true);
            } catch (IOException e) {
                logger.log(e.getMessage(), LogType.ERROR, true);
                throw new FileCannotBeUploadedException(e.getMessage());
            }
        }
    }

    public void deleteFile(String token, String fileName, UserEntity authEntity) throws IOException {
        fileRepository.delete(fileRepository.findFileByName(authEntity.getUsername(), fileName));
        logger.log("User " + authEntity.getUsername() + " deleted file " + fileName + '.', LogType.INFO, true);
    }

    public void putFile(String token, String fileName, UserEntity authEntity) throws IOException {
        FileEntity file = fileRepository.findFileByName(authEntity.getUsername(), fileName);
        file.setFileName(fileName);
        fileRepository.save(file);
        logger.log("User " + authEntity.getUsername() + " changed file " + fileName + '.', LogType.INFO, true);
    }
}
