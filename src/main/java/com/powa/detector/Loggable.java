package com.powa.detector;

public interface Loggable {

    default void warn(String s) {
        System.out.println("WARN: " + s);
    }

    default void error(String s) {
        System.out.println("ERROR: " + s);
    }

    default void info(String s) {
        System.out.println("INFO:" + s);
    }

}
