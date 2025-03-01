package com.jsonwebtoken.model;

import jakarta.persistence.Entity;
import jakarta.persistence.ManyToMany;

import java.util.List;

@Entity
public class Authority {
    private Long id;
    private String authority_name;

    @ManyToMany(mappedBy = "authorities")
    List<User> users;


    public Authority() {
    }

    public Authority(String authority_name) {
        this.authority_name = authority_name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getAuthority_name() {
        return authority_name;
    }

    public void setAuthority_name(String authority_name) {
        this.authority_name = authority_name;
    }

    public List<User> getUsers() {
        return users;
    }

    public void setUsers(List<User> users) {
        this.users = users;
    }
}
