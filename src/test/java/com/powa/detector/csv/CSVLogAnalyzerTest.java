package com.powa.detector.csv;

import static com.powa.detector.login.LoginTest.createFailures;
import static com.powa.detector.login.LoginTest.failure;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.time.LocalDateTime;
import java.util.List;

import org.junit.Test;
import org.mockito.Mockito;

import com.powa.detector.LogAnalyzer;
import com.powa.detector.SuspiciousLoginDetector;
import com.powa.detector.login.IPAddress;
import com.powa.detector.login.Login;
import com.powa.detector.login.LoginRepository;
import com.powa.detector.login.MapLoginRepository;

public class CSVLogAnalyzerTest {

    @Test
    public void successLineShouldReturnNull() {
        String line = "30.212.19.124,1336129421,SUCCESS,Thomas.Davenport";
        LogAnalyzer analyzer = new CSVLogAnalyzer(new MapLoginRepository(), new SuspiciousLoginDetector());
        assertNull(analyzer.parseLine(line));
    }

    @Test
    public void failureShouldReturnNull() {
        String line = "30.212.19.124,1336129421,FAILURE,Thomas.Davenport";
        LogAnalyzer analyzer = new CSVLogAnalyzer(new MapLoginRepository(), new SuspiciousLoginDetector());
        assertNull(analyzer.parseLine(line));
    }

    @Test
    public void suspiciousLoginShouldReturnIP() {
        List<Login> previuosFailures = createFailures(6, LocalDateTime.now());

        String line = "30.212.19.124,1336129421,FAILURE,Thomas.Davenport";
        String ip = "30.212.19.124";
        SuspiciousLoginDetector detector = Mockito.mock(SuspiciousLoginDetector.class);
        LoginRepository repository = Mockito.mock(LoginRepository.class);

        Mockito.when(repository.findByIP(new IPAddress(ip))).thenReturn(previuosFailures);

        Mockito.when(detector.suspiciousLogins(previuosFailures, failure(LocalDateTime.now()))).thenReturn(ip);
        LogAnalyzer analyzer = new CSVLogAnalyzer(repository, detector);
        assertEquals(ip, analyzer.parseLine(line));
    }
}
