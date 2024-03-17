package com.cloudcipher.cloudcipher_server.file.controller;

import com.cloudcipher.cloudcipher_server.file.service.FileService;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.Map;

@RestController
public class FileController {

    @Autowired
    private FileService fileService;


    @PostMapping("/upload")
    public @ResponseBody Map<String, Object> upload(@RequestParam String username, @RequestParam String token, @RequestParam MultipartFile file) {
        Map<String, Object> response = new HashMap<>();
        try {
            fileService.upload(username, token, file);
            response.put("success", "File uploaded successfully");
        } catch (BadCredentialsException | BadRequestException e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    @PostMapping("/download")
    public @ResponseBody Map<String, Object> download(@RequestParam String username, @RequestParam String token, @RequestParam String filename) {
        Map<String, Object> response = new HashMap<>();
        try {
            byte[] fileBytes = fileService.download(username, token, filename);
            response.put("fileBytes", fileBytes);
        } catch (BadCredentialsException | BadRequestException e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    @PostMapping("/delete")
    public @ResponseBody Map<String, Object> delete(@RequestParam String username, @RequestParam String token, @RequestParam String filename) {
        Map<String, Object> response = new HashMap<>();
        try {
            fileService.delete(username, token, filename);
            response.put("success", "File deleted successfully");
        } catch (BadCredentialsException | BadRequestException e) {
            response.put("error", e.getMessage());
        }
        return response;
    }
}
