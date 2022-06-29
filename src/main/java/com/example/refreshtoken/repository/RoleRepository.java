package com.example.refreshtoken.repository;

import com.example.refreshtoken.model.ERole;
import com.example.refreshtoken.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
