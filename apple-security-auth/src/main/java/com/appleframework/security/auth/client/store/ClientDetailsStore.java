package com.appleframework.security.auth.client.store;

import java.util.List;

import org.springframework.stereotype.Repository;

import com.appleframework.security.core.client.ClientDetails;

@Repository
public interface ClientDetailsStore {
	
   public ClientDetails loadClientByClientId(String clientId);
   
   public List<ClientDetails> findAll();
   	    
}