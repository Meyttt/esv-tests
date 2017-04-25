package ru.voskhod.tests.esv;

import org.apache.log4j.Logger;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.util.Date;

/**
 * Created by a.chebotareva on 17.04.2017.
 */
public class Runner {
    public static void main(String[] args) throws InvocationTargetException, IllegalAccessException, IOException {
        Logger logger = Logger.getLogger(Runner.class);
        logger.warn("Проверка ЕСВ от "+ new Date());
        SimpleTests simpleTests = new SimpleTests();
        Method[] tests= simpleTests.getClass().getDeclaredMethods();
        boolean error = false;
        for(Method method:tests){
           try{
               method.invoke(simpleTests);
           }catch (Exception e){
               logger.error("Проверка провалена. Причина: "+e.getMessage());
               error=true;
           }catch (AssertionError e1){
               logger.error("Проверка провалена. Причина: "+e1.getMessage());
               error=true;
           }
        }
        if(error){
            logger.error("Проверка провалена.");
        }else {
            logger.warn("Проверка прошла успешно.");
        }

    }
}
