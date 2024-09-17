package ru.netology.cloudservice;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import ru.netology.cloudservice.dao.UserEntity;
import ru.netology.cloudservice.exceptions.InvalidCredentialsException;
import ru.netology.cloudservice.jsonobjects.Credentials;
import ru.netology.cloudservice.repository.FileRepository;
import ru.netology.cloudservice.repository.UserRepository;
import ru.netology.cloudservice.service.CloudService;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class CloudServiceApplicationTests {
    private UserRepository userRepository;
    private FileRepository fileRepository;
    private UserDetailsService userDetailsService;
    private CloudService cloudService;
    BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    @BeforeEach
    void setUpBeforeClass() throws Exception {
        userRepository = Mockito.mock(UserRepository.class);
        fileRepository = Mockito.mock(FileRepository.class);
        userDetailsService = Mockito.mock(UserDetailsService.class);
        cloudService = new CloudService(fileRepository, userRepository, userDetailsService);
    }

    @Test
    void CloudServiceGetTokenWithoutPrefixTest() {
        String expectedToken = Instant.now().toEpochMilli() + "-" + UUID.randomUUID();
        String testToken = "Bearer " + expectedToken;

        String result = getTokenWithoutPrefix(testToken);

        Assertions.assertEquals(expectedToken, result);
    }

    @Test
    void CloudServiceLoginTest() throws JSONException, IOException {
        String login = "Admin";
        String testPassword = "admin";
        String encodePassword = bCryptPasswordEncoder.encode(testPassword);
        UserEntity user = new UserEntity();
        user.setUsername(login);
        user.setPassword(encodePassword);
        Mockito.when(userRepository.findByLogin(login)).thenReturn(user);

        ConcurrentHashMap<String, String> result = cloudService.login(new Credentials(login, testPassword), user);

        Assertions.assertNotNull(result);
    }

    @Test
    void CloudServiceLoginInvalidCredentialsTest() {
        String login = "Admin";
        String testLogin = "Adm";
        String testPassword = "admin";
        String encodePassword = bCryptPasswordEncoder.encode(testPassword);
        UserEntity user = new UserEntity();
        user.setUsername(login);
        user.setPassword(encodePassword);
        Mockito.when(userRepository.findByLogin(login)).thenReturn(user);

        Assertions.assertThrows(InvalidCredentialsException.class, () -> cloudService.login(new Credentials(testLogin, testPassword), user));
    }

    private String getTokenWithoutPrefix(String token) {
        if (token.startsWith("Bearer ")) {
            return token.substring("Bearer ".length());
        }
        return token;
    }
}
