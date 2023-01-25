package hitzseb.securitydemo.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import hitzseb.securitydemo.config.JwtService;
import hitzseb.securitydemo.user.Role;
import hitzseb.securitydemo.user.User;
import hitzseb.securitydemo.user.UserRepo;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
	private final UserRepo userRepo;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	
	public AuthResponse register(RegisterRequest request) {
	    var user = User.builder()
	        .firstname(request.getFirstname())
	        .lastname(request.getLastname())
	        .email(request.getEmail())
	        .password(passwordEncoder.encode(request.getPassword()))
	        .role(Role.USER)
	        .build();
	    userRepo.save(user);
	    var jwtToken = jwtService.generateToken(user);
	    return AuthResponse.builder()
	        .token(jwtToken)
	        .build();
	  }

	  public AuthResponse authenticate(AuthRequest request) {
	    authenticationManager.authenticate(
	        new UsernamePasswordAuthenticationToken(
	            request.getEmail(),
	            request.getPassword()
	        )
	    );
	    var user = userRepo.findByEmail(request.getEmail())
	        .orElseThrow();
	    var jwtToken = jwtService.generateToken(user);
	    return AuthResponse.builder()
	        .token(jwtToken)
	        .build();
	  }

}
