package ru.voskhod.tests.esv;

import org.apache.log4j.Logger;
import org.testng.ITestContext;
import org.testng.ITestNGMethod;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.List;

public class TestBase {
    private static Logger logger = Logger.getLogger(TestBase.class);

    public Config config;

    @BeforeClass
    public void initTestData() throws IOException, SAXException {
        config = new Config(System.getProperty("config.properties.file"));
        //setHTTPLogging();
    }

    private void setHTTPLogging() {
        System.setProperty("com.sun.xml.ws.transport.http.client.HttpTransportPipe.dump", "true");
        System.setProperty("com.sun.xml.internal.ws.transport.http.client.HttpTransportPipe.dump", "true");
        System.setProperty("com.sun.xml.ws.transport.http.HttpAdapter.dump", "true");
        System.setProperty("com.sun.xml.internal.ws.transport.http.HttpAdapter.dump", "true");
    }

    @BeforeMethod
    public void logMethodDescription(ITestContext cont, Method m) {
        ITestNGMethod[] testMethods = cont.getAllTestMethods();
        for (ITestNGMethod testMethod : testMethods) {
            if (testMethod.getMethodName().equals(m.getName())) {
                if (testMethod.getDescription() != null) {
                    logger.info("Новый тест: " + testMethod.getDescription());
                }
            }
        }
    }

    @AfterMethod
    public void logMethodResult(ITestContext cont, Method m) {
        Collection<ITestNGMethod> passed = cont.getPassedTests()
                .getAllMethods();
        Collection<ITestNGMethod> failed = cont.getFailedTests()
                .getAllMethods();
        Collection<ITestNGMethod> skipped = cont.getSkippedTests()
                .getAllMethods();

        for (ITestNGMethod testMethod : failed) {
            if (testMethod.getMethodName().equals(m.getName())) {
                List<Integer> numbers = testMethod
                        .getFailedInvocationNumbers();
                if (numbers.size() == 0) {
                    logger.info("Результат: Провален");
                    return;
                }
                for (int i = 0; i < numbers.size(); i++) {
                    int num = numbers.get(i);
                    if ((testMethod.getCurrentInvocationCount() - 1) == num) {
                        logger.info("Результат: Провален");
                        return;
                    }
                }
            }
        }

        for (ITestNGMethod testMethod : passed) {
            if (testMethod.getMethodName().equals(m.getName())) {
                logger.info("Результат: Пройден");
                return;
            }
        }

        for (ITestNGMethod testMethod : skipped) {
            if (testMethod.getMethodName().equals(m.getName())) {
                logger.info("Результат: Пропущен");
                return;
            }
        }
    }

}
