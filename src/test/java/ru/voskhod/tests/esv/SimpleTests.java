package ru.voskhod.tests.esv;


import org.apache.commons.codec.binary.StringUtils;
import org.apache.log4j.Logger;
import org.testng.Assert;
import org.testng.ITestResult;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import ru.rt.server.esv.VerificationResult;
import ru.rt.server.esv.VerificationResultWithReport;
import ru.rt.server.esv.VerificationResultWithSignedReport;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Date;


public class SimpleTests extends TestBase {

    private static Logger logger = Logger.getLogger(TestBase.class);
    private Client client;
    static boolean fail = false;

    public SimpleTests() throws IOException {
    }


//    public SimpleTests() throws  IOException {
//        client=new Client(config);
//    }

    @BeforeClass
    public void initClient() throws MalformedURLException {
        client=new Client(config);
        logger.info("Проверка сервиса проверки подписей от "+ new Date());
    }

                                                            /* Certificate */
//Корректный сертификат

    //TODO логирование тел сообщений на уровне trace: logger.trace
    //TODO добавить description
    //TODO обновить testng.xml

    @Test (description = "GUTS-ESV1: Проверка корректного сертификата")
     public void verifyCertificate() throws IOException {
        VerificationResult verificationResult = client.verifyCertificate(Common.readFromFile("data/Боевой сертификат.cer"));

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром");
    }

    @Test (description = "GUTS-ESV2: Проверка корректного сертификата с отчетом")
    public void verifyCertificateWithReport() throws IOException  {
        VerificationResultWithReport verificationResultWithReport = client.verifyCertificateWithReport(Common.readFromFile("data/Боевой сертификат.cer"));

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подлинность сертификата ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test (description = "GUTS-ESV3: Проверка корректного сертификата с подписанным отчетом")
    public void verifyCertificateWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCertificateWithSignedReport(Common.readFromFile("data/Боевой сертификат.cer"));

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
        Assert.assertTrue(report.contains("E3F6B7BCB969A79449ACC12C78ADC20AC9D15AD945C8127B91AC25F7CB3AA2B1"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Revoked сертификат аккредитованного УЦ

    @Test (description = "GUTS-ESV4: Проверка Revoked сертификата аккредитованного УЦ")
    public void verifyRevokedCertificate() throws IOException {
        VerificationResult verificationResult = client.verifyCertificate(Common.readFromFile("data/Отозванный сертификат.cer"));

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 7);
        Assert.assertEquals(verificationResult.getDescription(), "Один из сертификатов цепочки аннулирован");
    }

    @Test (description = "GUTS-ESV5: Проверка Revoked сертификата аккредитованного УЦ с отчетом")
    public void verifyRevokedCertificateWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCertificateWithReport(Common.readFromFile("data/Отозванный сертификат.cer"));

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 7);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Один из сертификатов цепочки аннулирован");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подлинность сертификата НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("Сертификат был отозван"));
    }

    @Test (description = "GUTS-ESV6: Проверка Revoked сертификата аккредитованного УЦ с подписанным отчетом")
    public void verifyRevokedCertificateWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCertificateWithSignedReport(Common.readFromFile("data/Отозванный сертификат.cer"));

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 7);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Один из сертификатов цепочки аннулирован");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("Сертификат был отозван"));
        Assert.assertTrue(report.contains("FB5E1E36C4E2242389CBCD33FCD67FFA13D22F7F98DE53047B36F0FCB7645D04"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректный сертификат неаккредитованного УЦ

    @Test (description = "GUTS-ESV7: Проверка корректного сертификата неаккредитованного УЦ")
    public void verifyMyCertificate() throws IOException {
        VerificationResult verificationResult = client.verifyCertificate(Common.readFromFile("data/Мой сертификат.cer"));

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 15);
        Assert.assertEquals(verificationResult.getDescription(), "Сертификат был выдан не аккредитованным УЦ/не доверенным УЦ");
    }

    @Test (description = "GUTS-ESV8: Проверка корректного сертификата неаккредитованного УЦ с отчетом")
    public void verifyMyCertificateWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCertificateWithReport(Common.readFromFile("data/Мой сертификат.cer"));

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 15);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Сертификат был выдан не аккредитованным УЦ/не доверенным УЦ");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подлинность сертификата НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Сертификат был выдан не аккредитованным УЦ/не доверенным УЦ"));
    }

    @Test (description = "GUTS-ESV7: Проверка корректного сертификата неаккредитованного УЦ с подписанным отчетом")
    public void verifyMyCertificateWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCertificateWithSignedReport(Common.readFromFile("data/Мой сертификат.cer"));

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 15);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Сертификат был выдан не аккредитованным УЦ/не доверенным УЦ");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("B0F9ACD0462519F72D1A241E1D665704F62C7500A9142620FB3FDE551C47A6D2"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректный сертификат


//Просроченный сертификат

    @Test (description = "GUTS-ESV13: Проверка просроченного сертификата")
    public void verifyBadSignature1Certificate() throws IOException {
        VerificationResult verificationResult = client.verifyCertificate(Common.readFromFile("data/Некорректный сертификат КриптоПро.cer"));

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 5);
        Assert.assertEquals(verificationResult.getDescription(), "Срок действия одного из сертификатов цепочки истек или еще не наступил");
    }

    @Test (description = "GUTS-ESV14: Проверка просроченного сертификата с отчетом")
    public void verifyBadSignature1CertificateWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCertificateWithReport(Common.readFromFile("data/Некорректный сертификат КриптоПро.cer"));

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 5);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Срок действия одного из сертификатов цепочки истек или еще не наступил");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подлинность сертификата НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Срок действия одного из сертификатов цепочки истек или еще не наступил"));
    }

    @Test (description = "GUTS-ESV15: Проверка просроченного сертификата с подписанным отчетом")
    public void verifyBadSignature1CertificateWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCertificateWithSignedReport(Common.readFromFile("data/Некорректный сертификат КриптоПро.cer"));

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 5);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Срок действия одного из сертификатов цепочки истек или еще не наступил");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("9B7D448059C70170F1F8F4D0A9BB391C622FF95DDC1B2809BA692CF011DB9328"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

                                                            /* CMS Attached */
//Корректная подпись false

    @Test (description = "GUTS-ESV16: Проверка корректного CMS с признаком false")
    public void verifyCMSfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS Корректный.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test (description = "GUTS-ESV17: Проверка корректного CMS с признаком false с отчетом")
    public void verifyCMSSignatureWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS Корректный.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test (description = "GUTS-ESV18: Проверка корректного CMS с признаком false с подписанным отчетом")
    public void verifyCMSSignatureWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS Корректный.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
        Assert.assertTrue(report.contains("0168162A651E64D51F251C7A075031977F9EE700D83C5E246112ADB7B9E46A35"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

// Корректная подпись true

    @Test (description = "GUTS-ESV19: Проверка корректного CMS с признаком true")
    public void verifyCMStrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS Корректный.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test (description = "GUTS-ESV20: Проверка корректного CMS с признаком true с отчетом")
    public void verifyCMSSignature1WithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS Корректный.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test (description = "GUTS-ESV21: Проверка корректного CMS с признаком true с подписанным отчетом")
    public void verifyCMSSignature1WithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS Корректный.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("0168162A651E64D51F251C7A075031977F9EE700D83C5E246112ADB7B9E46A35"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test (description = "GUTS-ESV22: Проверка некорректного CMS с признаком false")
    public void verifyBadSignatureCMSfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS Некорректный.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 1);
        Assert.assertEquals(verificationResult.getDescription(), "Внутренняя ошибка");
    }

    @Test (description = "GUTS-ESV23: Проверка некорректного CMS с признаком false с отчетом")
    public void verifyBadSignatureCMSSignatureWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS Некорректный.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Внутренняя ошибка");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test (description = "GUTS-ESV24: Проверка некорректного CMS с признаком false с подписанным отчетом")
    public void verifyBadSignatureCMSSignatureWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS Некорректный.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Внутренняя ошибка");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("7413E7FEB7A32A0FC5C35C6FC211ADBF74F44CFDD875577249ACCAA77AB72B52"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test (description = "GUTS-ESV25: Проверка некорректного CMS с признаком true")
    public void verifyBadSignatureCMStrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS Некорректный.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 1);
        Assert.assertEquals(verificationResult.getDescription(), "Внутренняя ошибка");
    }

    @Test (description = "GUTS-ESV26: Проверка некорректного CMS с признаком true с отчетом")
    public void verifyBadSignature1CMSSignatureWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Внутренняя ошибка");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test (description = "GUTS-ESV27: Проверка некорректного CMS с признаком true с подписанным отчетом")
    public void verifyBadSignature1CMSSignatureWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Внутренняя ошибка");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("7413E7FEB7A32A0FC5C35C6FC211ADBF74F44CFDD875577249ACCAA77AB72B52"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись Revoked false

    //Некорректная подпись false

    @Test (description = "GUTS-ESV28: Проверка CMS, Revoked с признаком false")
    public void verifyRevokedSignatureCMSfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS Отозванный.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(),13);
        Assert.assertEquals(verificationResult.getDescription(), "Сертификат подписи недействителен");
    }

    @Test (description = "GUTS-ESV29: Проверка CMS, Revoked с признаком false с отчетом")
    public void verifyRevokedSignatureCMSSignatureWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS Отозванный.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 13);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Сертификат подписи недействителен");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Один из сертификатов цепочки аннулирован"));
    }

    @Test (description = "GUTS-ESV30: Проверка CMS, Revoked с признаком false с подписанным отчетом")
    public void verifyRevokedSignatureCMSSignatureWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS Отозванный.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 13);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Сертификат подписи недействителен");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Один из сертификатов цепочки аннулирован"));
        Assert.assertTrue(report.contains("1FC5B5EAF9B79FA6699BCB7511677A096610BE380B7EA0D9BF49CC54035B093C"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }
//Некорректная подпись1 false

    @Test (description = "GUTS-ESV34: Проверка некорректного 1 CMS с признаком false")
    public void verifyBadSignatureCMSfalse1() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS Некорректный1.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 1);
        Assert.assertEquals(verificationResult.getDescription(), "Внутренняя ошибка");
    }

    @Test (description = "GUTS-ESV36: Проверка некорректного 1 CMS с признаком false с подписанным отчетом")
    public void verifyBadSignatureCMSSignature1WithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS Некорректный1.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Внутренняя ошибка");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("DEBECBC7767EA33912B531435590CAB3F1132E43DF41A2E5002FFF709EF63921"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись1 true

    @Test (description = "GUTS-ESV37: Проверка некорректного 1 CMS с признаком true")
    public void verifyBadSignatureCMStrue1() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS Некорректный1.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 1);
        Assert.assertEquals(verificationResult.getDescription(), "Внутренняя ошибка");
    }

    @Test (description = "GUTS-ESV39: Проверка некорректного 1 CMS с признаком true с подписанным отчетом")
    public void verifyBadSignature1CMSSignature1WithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS Некорректный1.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Внутренняя ошибка");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("DEBECBC7767EA33912B531435590CAB3F1132E43DF41A2E5002FFF709EF63921"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

                                                            /* CMS Detached */

//Корректная подпись false


    @Test (description = "GUTS-ESV40: Проверка корректного CMS Detached с признаком false")
    public void verifyCMSDetachedfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureDetached(Common.readFromFile("data/CMS Detached Боевой.sig"), Common.readFromFile("data/Тестирование ИС ГУЦ.rtf"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test (description = "GUTS-ESV41: Проверка корректного CMS Detached с признаком false с отчетом")
    public void verifyCMSSignatureDetachedWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureDetachedWithReport(Common.readFromFile("data/CMS Detached Боевой.sig"), Common.readFromFile("data/Тестирование ИС ГУЦ.rtf"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test (description = "GUTS-ESV42: Проверка корректного CMS Detached с признаком false с подписанным отчетом")
    public void verifyCMSSignature1DetachedWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached Боевой.sig"), Common.readFromFile("data/Тестирование ИС ГУЦ.rtf"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
        Assert.assertTrue(report.contains("CCEDFAA77E01C19454E98E1355BE119B6113878AA5F6FCEF69BF608744114C1D"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test (description = "GUTS-ESV43: Проверка корректного CMS Detached с признаком true")
    public void verifyCMSDetachedtrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureDetached(Common.readFromFile("data/CMS Detached Боевой.sig"), Common.readFromFile("data/Тестирование ИС ГУЦ.rtf"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test (description = "GUTS-ESV44: Проверка корректного CMS Detached с признаком true с отчетом")
    public void verify1CMSSignatureDetachedWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureDetachedWithReport(Common.readFromFile("data/CMS Detached Боевой.sig"), Common.readFromFile("data/Тестирование ИС ГУЦ.rtf"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test (description = "GUTS-ESV45: Проверка корректного CMS Detached с признаком true с подписанным отчетом")
    public void verifyCMSSignatureDetachedWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached Боевой.sig"), Common.readFromFile("data/Тестирование ИС ГУЦ.rtf"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("CCEDFAA77E01C19454E98E1355BE119B6113878AA5F6FCEF69BF608744114C1D"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test (description = "GUTS-ESV46: Проверка некорректного CMS Detached с признаком false")
    public void verifyBadSignatureCMSDetachedfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureDetached(Common.readFromFile("data/CMS Detached Боевой.sig"), Common.readFromFile("data/CMS Detached1.jpg"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test (description = "GUTS-ESV47: Проверка некорректного CMS Detached с признаком false с отчетом")
    public void verifyBadSignatureCMSSignature1DetachedWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureDetachedWithReport(Common.readFromFile("data/CMS Detached Боевой.sig"), Common.readFromFile("data/CMS Detached1.jpg"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test (description = "GUTS-ESV48: Проверка некорректного CMS Detached с признаком false с подписанным отчетом")
    public void verifyBadSignatureCMSSignatureDetachedWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached Боевой.sig"), Common.readFromFile("data/CMS Detached1.jpg"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("CCEDFAA77E01C19454E98E1355BE119B6113878AA5F6FCEF69BF608744114C1D"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test (description = "GUTS-ESV50: Проверка некорректного CMS Detached с признаком true с отчетом")
    public void verifyBadSignature1CMSSignature1DetachedWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureDetachedWithReport(Common.readFromFile("data/CMS Detached Боевой.sig"), Common.readFromFile("data/CMS Detached1.jpg"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test (description = "GUTS-ESV51: Проверка некорректного CMS Detached с признаком true с подписанным отчетом")
    public void verifyBadSignature1CMSSignatureDetachedWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached Боевой.sig"), Common.readFromFile("data/CMS Detached1.jpg"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("CCEDFAA77E01C19454E98E1355BE119B6113878AA5F6FCEF69BF608744114C1D"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись Revoked

    //Некорректная подпись false

    @Test (description = "GUTS-ESV52: Проверка CMS Detached, Revoked с признаком false")
    public void verifyRevokedSignatureCMSDetachedfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureDetached(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS Detached.jpg"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 13);
        Assert.assertEquals(verificationResult.getDescription(), "Сертификат подписи недействителен");
    }
//Некорректная подпись true

    @Test (description = "GUTS-ESV55: Проверка CMS Detached, Revoked с признаком true")
    public void verifyRevokedSignatureCMSDetachedtrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureDetached(Common.readFromFile("data/CMS Detached Отозванный.sig"), Common.readFromFile("data/Тестирование ИС ГУЦ.rtf"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test (description = "GUTS-ESV56: Проверка CMS Detached, Revoked с признаком true с отчетом")
    public void verifyRevokedSignature1CMSSignature1DetachedWithReport() throws IOException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureDetachedWithReport(Common.readFromFile("data/CMS Detached Отозванный.sig"), Common.readFromFile("data/Тестирование ИС ГУЦ.rtf"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.trace("repstr: " + report);
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test (description = "GUTS-ESV57: Проверка CMS Detached, Revoked с признаком true с подписанным отчетом")
    public void verifyRevokedSignature1CMSSignatureDetachedWithSignedReport() throws IOException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached Отозванный.sig"), Common.readFromFile("data/Тестирование ИС ГУЦ.rtf"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.trace("repstr: " + report);
        logger.trace("signstr: " + signature);
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("E28DA659FF327EE74306FBDA5AC0BE9035AB1F18D468853EE52BD4EE7C4C6F54"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }
    @AfterMethod(alwaysRun = true)
    public static void setRes(ITestResult testResult){
        if (!testResult.isSuccess()){
            fail = true;
        }
    }
    @AfterClass
    public static void writeResult() throws IOException {
        File log = new File(new File(".").getAbsolutePath()+"\\..\\"+"log.txt");
        FileWriter fileWriter = new FileWriter(log,true);
        if(fail){
            fileWriter.append("Проверка сервиса проверки подписей провалена\r\n");
        }else {
            fileWriter.append("Проверка сервиса проверки подписей прошла успешно\r\n");

        }
        fileWriter.flush();
    }


}

