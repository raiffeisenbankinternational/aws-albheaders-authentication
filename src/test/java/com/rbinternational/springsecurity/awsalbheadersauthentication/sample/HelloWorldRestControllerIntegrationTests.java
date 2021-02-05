package com.rbinternational.springsecurity.awsalbheadersauthentication.sample;

import com.rbinternational.springsecurity.awsalbheadersauthentication.AWSAlbHeadersAuthenticationConverter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class HelloWorldRestControllerIntegrationTests {

    @Autowired
    private HelloWorldRestController controller;

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testContextLoads() {
        assertThat(controller).isNotNull();
    }

    @Test
    public void testHelloAdminUserIsForbidden() throws Exception {
        mockMvc.perform(get("/helloadminuser")
                .header(AWSAlbHeadersAuthenticationConverter.SUB_HEADER, "sub")
                .header(AWSAlbHeadersAuthenticationConverter.ACCESS_TOKEN_HEADER, "access")
                .header(AWSAlbHeadersAuthenticationConverter.USER_CLAIMS_HEADER, "userclaims")
        ).andExpect(status().isForbidden());
    }

    @Test
    public void testHelloOk() throws Exception {
        mockMvc.perform(get("/hello")
                .header(AWSAlbHeadersAuthenticationConverter.SUB_HEADER, "sub")
                .header(AWSAlbHeadersAuthenticationConverter.ACCESS_TOKEN_HEADER, "access")
                .header(AWSAlbHeadersAuthenticationConverter.USER_CLAIMS_HEADER, "userclaims")
        ).andExpect(status().isOk());
    }

    @Test
    public void testHelloWoutRequestHeadersReturnsStatusUnauthenticated() throws Exception {
        mockMvc.perform(get("/hello")).andExpect(status().isUnauthorized());
    }
}
