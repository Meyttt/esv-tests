package ru.voskhod.tests.esv;

import org.apache.log4j.Logger;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import ru.rt.server.esv.VerificationResult;

import java.io.IOException;
import java.net.MalformedURLException;

public class SimpleTests extends TestBase {

    private static Logger logger = Logger.getLogger(TestBase.class);

    private Client client;

    @BeforeClass
    public void initClient() throws MalformedURLException {
        client = new Client(config);
    }

    @Test
    public void verifyCertificate() throws IOException {
        VerificationResult verificationResult = client.verifyCertificate(Common.readFromFile("data/MakarovDA00.crt"));

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 15);
        Assert.assertEquals(verificationResult.getDescription(), "Сертификат был выдан не аккредитованным УЦ/не доверенным УЦ");
    }
}
