package com.powa.detector.login;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.time.LocalDateTime;

import org.junit.Before;
import org.junit.Test;

public class MapLoginRepositoryTest {

    private LoginRepository repository;
    private IPAddress ip1 = new IPAddress("10.10.10.10");
    private IPAddress ip2 = new IPAddress("11.11.11.11");

    @Before
    public void resetRepo() {
        repository = new MapLoginRepository();
    }

    @Test
    public void shouldAddNewLogin_ThenFind() {
        repository.save(new Login("userName", LoginResult.SUCCESS, ip1, LocalDateTime.now()));
        assertNotNull(repository.findByIP(ip1));
        assertNull(repository.findByIP(ip2));
    }

    @Test
    public void shouldAddToExistingLogins() {
        repository.save(new Login("userName", LoginResult.SUCCESS, ip1, LocalDateTime.now()));
        repository.save(new Login("userName", LoginResult.FAILURE, ip1, LocalDateTime.now()));
        assertEquals(2, repository.findByIP(ip1).size());
    }
}
