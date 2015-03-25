package com.powa.detector;

import static com.powa.detector.login.LoginTest.createFailures;
import static com.powa.detector.login.LoginTest.failure;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.powa.detector.login.IPAddress;
import com.powa.detector.login.Login;
import com.powa.detector.login.LoginResult;

public class SuspicousLoginDetectorTest {

    private SuspiciousLoginDetector detector = new SuspiciousLoginDetector();
    private String userName = "hello";
    private IPAddress source = new IPAddress("30.212.19.124");

    @Test
    public void firstFailedNotSuspicious() {
        assertNull(detector.suspiciousLogins(new ArrayList<Login>(), failure(LocalDateTime.now())));
        assertNull(detector.suspiciousLogins(null, failure(LocalDateTime.now())));
    }

    @Test
    public void lessThanFiveNotSuspicious() {
        List<Login> previous = createFailures(3, LocalDateTime.now().minusMinutes(1));
        assertNull(detector.suspiciousLogins(previous, failure(LocalDateTime.now())));
    }

    @Test
    public void fiveFailedIsSuspicious() {
        List<Login> previous = createFailures(4, LocalDateTime.now().minusMinutes(1));
        assertEquals(source.toString(), detector.suspiciousLogins(previous, failure(LocalDateTime.now())));
    }

    @Test
    public void fiveFailedOutsidePeriod_NotSuspicious() {
        List<Login> previous = createFailures(5, LocalDateTime.now().minusMinutes(10));
        assertNull(detector.suspiciousLogins(previous, failure(LocalDateTime.now())));
    }

    @Test
    public void successLogin_NotSuspicious() {
        List<Login> previous = createFailures(3, LocalDateTime.now().minusMinutes(10));
        previous.add(new Login(userName, LoginResult.SUCCESS, source, LocalDateTime.now()));
        previous.add(new Login(userName, LoginResult.SUCCESS, source, LocalDateTime.now()));
        previous.add(new Login(userName, LoginResult.SUCCESS, source, LocalDateTime.now()));
        assertNull(detector.suspiciousLogins(previous, failure(LocalDateTime.now())));
    }

}
