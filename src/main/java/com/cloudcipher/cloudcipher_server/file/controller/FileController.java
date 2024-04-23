package com.cloudcipher.cloudcipher_server.file.controller;

import com.cloudcipher.cloudcipher_server.file.service.FileService;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@RestController
public class FileController {

    @Autowired
    private FileService fileService;


    @PostMapping("/upload")
    public @ResponseBody String upload(@RequestParam String username, @RequestParam String token, @RequestParam MultipartFile file, @RequestParam MultipartFile iv) {
        try {
            fileService.upload(username, token, file, iv);
            return "File uploaded successfully";
        } catch (BadCredentialsException | BadRequestException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping(
            value = "/download",
            produces = MediaType.APPLICATION_OCTET_STREAM_VALUE
    )
    public @ResponseBody byte[] download(@RequestParam String username, @RequestParam String token, @RequestParam String filename) {
        try {
            return fileService.download(username, token, filename);
        } catch (BadCredentialsException | BadRequestException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/delete")
    public @ResponseBody String delete(@RequestParam String username, @RequestParam String token, @RequestParam String filename) {
        try {
            fileService.delete(username, token, filename);
            return "File deleted successfully";
        } catch (BadCredentialsException | BadRequestException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/reencrypt")
    public @ResponseBody String reEncrypt(@RequestParam String username, @RequestParam String targetUsername, @RequestParam String token, @RequestParam String filename, @RequestParam MultipartFile iv, @RequestParam MultipartFile rg) {
        try {
            fileService.reEncrypt(username, targetUsername, token, filename, iv, rg);
            return "File re-encrypted successfully";
        } catch (BadCredentialsException | IOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/list")
    public @ResponseBody List<Map<String, String>> list(@RequestParam String username, @RequestParam String token) {
        try {
            return fileService.list(username, token);
        } catch (BadCredentialsException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }
}
