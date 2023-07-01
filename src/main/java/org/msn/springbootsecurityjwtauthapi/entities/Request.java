package org.msn.springbootsecurityjwtauthapi.entities;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @AllArgsConstructor @NoArgsConstructor
public class Request {
	
	private String userName;
	private String userPwd;
	private List<String> roles;

}
