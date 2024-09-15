package ru.netology.cloudservice.controller;

import lombok.AllArgsConstructor;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.netology.cloudservice.jsonobjects.Credentials;
import ru.netology.cloudservice.dao.FileEntity;
import ru.netology.cloudservice.jsonobjects.FileList;
import ru.netology.cloudservice.service.CloudService;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/")
@AllArgsConstructor
public class CloudController {
    private final CloudService service;


    @PostMapping("login")
    public ConcurrentHashMap<String, String> login(@RequestBody Credentials credentials) {
        try {
            return service.login(credentials);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return null;
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @PostMapping("logout")
    public void logout(@RequestHeader(name = "auth-token") String token) {
        service.logout(token);
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @GetMapping("list")
    public List<FileList> list(@RequestHeader(name = "auth-token") String token,
                               @RequestParam("limit") Integer limit) {
        return service.list(token, limit);
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @PostMapping("file")
    public void postFile(@RequestHeader(name = "auth-token") String token,
                           @RequestParam("filename") String fileName,
                           @RequestBody MultipartFile file) {
        service.postFile(token, fileName, file);
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @DeleteMapping("file")
    public void deleteFile(@RequestHeader(name = "auth-token") String token,
                             @RequestParam("filename") String fileName) {
        service.deleteFile(token, fileName);
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @PutMapping("file")
    public void putFile(@RequestHeader(name = "auth-token") String token,
                          @RequestParam("filename") String fileName) {
        service.putFile(token, fileName);
    }

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @GetMapping("file")
    public byte[] getFile(@RequestHeader(name = "auth-token") String token,
                        @RequestParam("filename") String fileName) throws IOException {
        return service.getFile(token, fileName);
    }
}
