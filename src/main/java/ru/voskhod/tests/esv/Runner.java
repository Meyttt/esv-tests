package ru.voskhod.tests.esv;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;

/**
 * Created by a.chebotareva on 17.04.2017.
 */
public class Runner {
    public static void main(String[] args) throws InvocationTargetException, IllegalAccessException, IOException {
        SimpleTests simpleTests = new SimpleTests();
        Method[] tests= simpleTests.getClass().getDeclaredMethods();
        for(Method method:tests){
            method.invoke(simpleTests);
        }
    }
}
