package com.social.securitydemo;

import com.social.securitydemo.jwt.JwtUtils;
import com.social.securitydemo.jwt.LoginRequest;
import com.social.securitydemo.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetingsController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String userEndPoint() {
        return "hello USER";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminEndPoint() {
        return "hello ADMIN !";
    }


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword())
            );

        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("Status", false);

            return new ResponseEntity<Object>(map, HttpStatus.UNAUTHORIZED);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        LoginResponse loginResponse = new LoginResponse(jwtToken, roles, userDetails.getUsername());

        return new ResponseEntity<LoginResponse>(loginResponse, HttpStatus.OK);

    }


}
