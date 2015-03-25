package com.powa.detector.csv;

import java.util.List;

import com.powa.detector.LogAnalyzer;
import com.powa.detector.Loggable;
import com.powa.detector.SuspiciousLoginDetector;
import com.powa.detector.login.Login;
import com.powa.detector.login.LoginRepository;

public class CSVLogAnalyzer implements LogAnalyzer, Loggable {

    private static final String COMMA = ",";
    private LoginRepository repository;
    private SuspiciousLoginDetector detector;

    public CSVLogAnalyzer(LoginRepository repository, SuspiciousLoginDetector detector) {
        super();
        this.repository = repository;
        this.detector = detector;
    }

    @Override
    public String parseLine(String line) {
        String[] log = line.split(COMMA);
        Login login = new Login(log);
        String ip;

        if (login.isFailed()) {
            warn("Found failed login for user " + login.getUserName());
            List<Login> logins = repository.findByIP(login.getSource());
            ip = detector.suspiciousLogins(logins, login);
        } else {
            info("Successful login for " + login.getUserName());
            ip = null;
        }

        info("Returning ip " + ip);
        repository.save(login);
        return ip;
    }

}
