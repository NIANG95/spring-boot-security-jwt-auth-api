package org.msn.springbootsecurityjwtauthapi.repository;

import java.util.Optional;

import org.msn.springbootsecurityjwtauthapi.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByUserName(String userName);
}
