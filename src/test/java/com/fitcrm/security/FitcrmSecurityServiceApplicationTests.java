package com.fitcrm.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = FitcrmSecurityServiceApplication.class)
@ActiveProfiles("test")
class FitcrmSecurityServiceApplicationTests {

	@Test
	void contextLoads(@Autowired ApplicationContext applicationContext) {
		assertThat(applicationContext).isNotNull();
	}

}
