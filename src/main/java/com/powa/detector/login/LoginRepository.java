package com.powa.detector.login;

import java.util.List;

public interface LoginRepository {

    void save(Login login);

    List<Login> findByIP(IPAddress ip);

}
