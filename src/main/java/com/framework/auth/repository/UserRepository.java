package com.framework.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.framework.auth.domain.UserDomain;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserDomain, Long> {

    Optional<UserDomain> findByEmail(String email);

}
