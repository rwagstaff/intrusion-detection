package com.powa.detector;

import java.util.List;

import com.powa.detector.login.Login;

public class SuspiciousLoginDetector implements Loggable {

    private static final int SUSPICIOUS_LOGIN_MAX = 5;

    public String suspiciousLogins(List<Login> previousLogins, Login failedLogin) {
        if (previousLogins == null || previousLogins.isEmpty()) {
            info("No previous logins");
            return null;
        }

        if (numberWithinPeriod(previousLogins, failedLogin) >= SUSPICIOUS_LOGIN_MAX) {
            error("Detected suspecious login, reporting ip address " + failedLogin.getSource());
            return failedLogin.getSource().toString();
        } else {
            info("Failed login but not suspicious");
            return null;
        }
    }

    private int numberWithinPeriod(List<Login> previousLogins, Login failedLogin) {
        int suspiciousCount = 0;
        for (Login login : previousLogins) {
            if (login.isSuspicious(failedLogin)) {
                suspiciousCount++;
            }
        }
        // Add one because the current login has failed aswell
        suspiciousCount++;

        info("Found " + suspiciousCount + " Suspicious logins");
        return suspiciousCount;

    }
}
