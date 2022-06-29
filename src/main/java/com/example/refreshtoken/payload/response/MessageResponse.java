package com.example.refreshtoken.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@AllArgsConstructor
@NotBlank
public class MessageResponse {
	private String message;


}
