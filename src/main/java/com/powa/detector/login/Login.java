package com.powa.detector.login;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

public class Login {

    private static final int PERIOD_MINS = 5;

    private String userName;
    private LoginResult action;
    private IPAddress source;
    private LocalDateTime time;

    public Login(String[] log) {
        this.source = new IPAddress(log[0]);
        this.time = LocalDateTime.ofInstant(Instant.ofEpochMilli(Long.valueOf(log[1])), ZoneId.systemDefault());
        this.action = LoginResult.valueOf(log[2]);
        this.userName = log[3];
    }

    public Login(String userName, LoginResult action, IPAddress source, LocalDateTime time) {
        super();
        this.userName = userName;
        this.action = action;
        this.source = source;
        this.time = time;
    }

    public IPAddress getSource() {
        return source;
    }

    public String getUserName() {
        return userName;
    }

    public boolean isFailed() {
        return action == LoginResult.FAILURE;
    }

    private boolean isWithinTimePeriod(LocalDateTime login) {
        LocalDateTime max = login.plusMinutes(PERIOD_MINS);
        LocalDateTime min = login.minusMinutes(PERIOD_MINS);
        return time.isAfter(min) && time.isBefore(max);
    }

    public boolean isSuspicious(Login login) {
        // A login is suspicious if its failed and within the specified period
        return isFailed() && isWithinTimePeriod(login.time) && login.isFailed() && login.source.equals(this.source);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((source == null) ? 0 : source.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Login other = (Login) obj;
        if (source == null) {
            if (other.source != null)
                return false;
        } else if (!source.equals(other.source))
            return false;
        return true;
    }
}
