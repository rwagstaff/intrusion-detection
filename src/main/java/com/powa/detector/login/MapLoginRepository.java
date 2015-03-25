package com.powa.detector.login;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MapLoginRepository implements LoginRepository {

    private Map<IPAddress, List<Login>> failedLogin = Collections.synchronizedMap(new HashMap<IPAddress, List<Login>>());

    @Override
    public void save(Login login) {
        IPAddress ip = login.getSource();
        if (failedLogin.containsKey(login.getSource())) {
            failedLogin.get(ip).add(login);
        } else {
            List<Login> logins = new ArrayList<Login>();
            logins.add(login);
            failedLogin.put(ip, logins);
        }
    }

    @Override
    public List<Login> findByIP(IPAddress ip) {
        return failedLogin.get(ip);
    }

}
