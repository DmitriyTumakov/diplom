package ru.netology.cloudservice.controller;

import lombok.AllArgsConstructor;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.netology.cloudservice.dao.FileEntity;
import ru.netology.cloudservice.service.CloudService;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/")
@AllArgsConstructor
public class CloudController {
    private final CloudService service;

    @PostMapping("login")
    public ConcurrentHashMap<String, String> login(@RequestBody ConcurrentHashMap<String, Object> credentials) {
        try {
            return service.login(credentials);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return null;
    }

    @PostMapping("logout")
    public void logout(@RequestHeader(name = "auth-token") String token) {
        service.logout(token);
    }

    @GetMapping("list")
    public List<FileEntity> list(@RequestHeader(name = "auth-token") String token,
                                 @RequestParam("limit") Integer limit) {
        return service.list(token, limit);
    }

    @PostMapping("file/post")
    public void postFile(@RequestHeader(name = "auth-token") String token,
                           @RequestParam("filename") String fileName,
                           @RequestBody MultipartFile file) {
        service.postFile(token, fileName, file);
    }

    @DeleteMapping("file/delete")
    public void deleteFile(@RequestHeader(name = "auth-token") String token,
                             @RequestParam("filename") String fileName) {
        service.deleteFile(token, fileName);
    }

    @PutMapping("file/put")
    public void putFile(@RequestHeader(name = "auth-token") String token,
                          @RequestParam("filename") String fileName) {
        service.putFile(token, fileName);
    }

    @GetMapping("file/get")
    public MultipartFile getFile(@RequestHeader(name = "auth-token") String token,
                          @RequestParam("filename") String fileName) {
        return service.getFile(token, fileName);
    }
}
