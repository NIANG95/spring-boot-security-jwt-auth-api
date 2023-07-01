package org.msn.springbootsecurityjwtauthapi.controllers;

import java.util.Set;
import java.util.stream.Collectors;

import org.msn.springbootsecurityjwtauthapi.entities.Request;
import org.msn.springbootsecurityjwtauthapi.entities.Response;
import org.msn.springbootsecurityjwtauthapi.exception.DisabledUserException;
import org.msn.springbootsecurityjwtauthapi.exception.InvalidUserCredentialsException;
import org.msn.springbootsecurityjwtauthapi.service.JwtUtil;
import org.msn.springbootsecurityjwtauthapi.service.UserAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin("*")
public class JwtRestApi {

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private UserAuthService userAuthService;

	@Autowired
	private AuthenticationManager authenticationManager;

	@PostMapping("/signin")
	public ResponseEntity<Response> generateJwtToken(@RequestBody Request request) {
		Authentication authentication = null;
		try {
			authentication = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(request.getUserName(), request.getUserPwd()));
		} catch (DisabledException e) {
			throw new DisabledUserException("User Inactive");
		} catch (BadCredentialsException e) {
			throw new InvalidUserCredentialsException("Invalid Credentials");
		}

		User user = (User) authentication.getPrincipal();
		Set<String> roles = user.getAuthorities().stream().map(r -> r.getAuthority()).collect(Collectors.toSet());

		String token = jwtUtil.generateToken(authentication);

		Response response = new Response();
		response.setToken(token);
		response.setRoles(roles.stream().collect(Collectors.toList()));

		return new ResponseEntity<Response>(response, HttpStatus.OK);
	}

	@PostMapping("/signup")
	public ResponseEntity<String> signup(@RequestBody Request request) {
		userAuthService.saveUser(request);

		return new ResponseEntity<String>("User successfully registered", HttpStatus.OK);
	}

}
