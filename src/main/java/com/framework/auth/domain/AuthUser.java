package com.framework.auth.domain;

import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

@Getter
public class AuthUser extends User {

    private String fullName;

    public AuthUser(UserDomain userDomain) {
        super(userDomain.getEmail(), userDomain.getPassword(), Collections.emptyList());
        this.fullName = userDomain.getUserName();
    }

}
