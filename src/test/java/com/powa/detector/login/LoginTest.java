package com.powa.detector.login;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Test;

public class LoginTest {

    public static final String IP = "30.212.19.124";
    public static final String USER_NAME = "Thomas.Davenport";
    public static final IPAddress source = new IPAddress(IP);
    private String success = "SUCCESS";
    private String failed = "FAILURE";
    private String oldDate = "1336129421";
    private String newDate = String.valueOf(Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant()).getTime());

    @Test
    public void shouldParseSuccessLogin() {
        Login login = new Login(new String[] { IP, oldDate, success, USER_NAME });
        assertEquals(USER_NAME, login.getUserName());
        assertFalse(login.isFailed());
        assertEquals(new IPAddress(IP), login.getSource());
    }

    @Test
    public void shouldParseFailedLogin() {
        Login login = new Login(new String[] { IP, oldDate, failed, USER_NAME });
        assertTrue(login.isFailed());
    }

    @Test
    public void suspiciousLogin_InPeriod() {
        Login login = new Login(new String[] { IP, newDate, failed, USER_NAME });
        Login otherLogin = new Login(USER_NAME, LoginResult.FAILURE, source, LocalDateTime.now().minusMinutes(1));
        assertTrue(login.isSuspicious(otherLogin));
    }

    @Test
    public void notSuspicious_OutsidePeriod() {
        Login login = new Login(new String[] { IP, newDate, failed, USER_NAME });
        Login otherLogin = new Login(USER_NAME, LoginResult.FAILURE, source, LocalDateTime.now().minusMinutes(6));
        assertFalse(login.isSuspicious(otherLogin));
    }

    @Test
    public void notSuspiciousWhenSuccessful() {
        Login login = new Login(new String[] { IP, newDate, failed, USER_NAME });
        Login otherLogin = new Login(USER_NAME, LoginResult.SUCCESS, source, LocalDateTime.now().minusMinutes(6));
        assertFalse(login.isSuspicious(otherLogin));
    }

    public static List<Login> createFailures(int logins, LocalDateTime time) {
        List<Login> failures = new ArrayList<>();
        for (int i = 0; i < logins; i++) {
            failures.add(failure(time));
        }
        return failures;
    }

    public static Login failure(LocalDateTime time) {
        return new Login(USER_NAME, LoginResult.FAILURE, source, time);
    }

}
