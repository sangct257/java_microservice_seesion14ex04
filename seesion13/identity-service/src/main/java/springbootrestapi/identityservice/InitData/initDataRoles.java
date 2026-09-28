package springbootrestapi.identityservice.InitData;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import springbootrestapi.identityservice.entity.Role;
import springbootrestapi.identityservice.repository.RoleRepository;

import java.util.List;

@Component
@RequiredArgsConstructor
public class initDataRoles implements CommandLineRunner {
    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        if (roleRepository.findAll().isEmpty()) {
            List<Role> roles = List.of(
                    new Role(null, "ROLE_USER"),
                    new Role(null, "ROLE_ADMIN"),
                    new Role(null, "ROLE_MODERATOR")
            );
            roleRepository.saveAll(roles);
            System.out.println("-------- Đã khởi tạo các role ban đầu --------->>>");
        }
    }
}
