package org.msn.springbootsecurityjwtauthapi.entities;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @AllArgsConstructor @NoArgsConstructor
public class Response {
	
	private String token;
	private List<String> roles;

}
