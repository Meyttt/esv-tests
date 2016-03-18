package ru.voskhod.tests.esv;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.Base64DecodingException;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import ru.rt.server.esv.VerificationResult;
import ru.rt.server.esv.VerificationResultWithReport;
import ru.rt.server.esv.VerificationResultWithSignedReport;


import java.io.IOException;
import java.net.MalformedURLException;

public class SimpleTests extends TestBase {

    private static Logger logger = Logger.getLogger(TestBase.class);

    private Client client;

    @BeforeClass
    public void initClient() throws MalformedURLException {
        client = new Client(config);
    }

                                                            /* Certificate */
//Корректный сертификат

    @Test
     public void verifyCertificate() throws IOException {
        VerificationResult verificationResult = client.verifyCertificate(Common.readFromFile("data/IS_GUTS_2016_1.cer"));

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром");
    }

    @Test
    public void verifyCertificateWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCertificateWithReport(Common.readFromFile("data/IS_GUTS_2016_1.cer"));

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подлинность сертификата ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyCertificateWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCertificateWithSignedReport(Common.readFromFile("data/IS_GUTS_2016_1.cer"));

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
        Assert.assertTrue(report.contains("7F6088280765F2BFB57115B7085AB8462899387B7019E5637C2785D348FF2110"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректный сертификат неаккредитованного УЦ

    @Test
    public void verifyMyCertificate() throws IOException {
        VerificationResult verificationResult = client.verifyCertificate(Common.readFromFile("data/Мой сертификат.cer"));

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 15);
        Assert.assertEquals(verificationResult.getDescription(), "Сертификат был выдан не аккредитованным УЦ/не доверенным УЦ");
    }

    @Test
    public void verifyMyCertificateWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCertificateWithReport(Common.readFromFile("data/Мой сертификат.cer"));

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 15);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Сертификат был выдан не аккредитованным УЦ/не доверенным УЦ");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подлинность сертификата НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Сертификат был выдан не аккредитованным УЦ/не доверенным УЦ"));
    }

    @Test
    public void verifyMyCertificateWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCertificateWithSignedReport(Common.readFromFile("data/Мой сертификат.cer"));

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 15);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Сертификат был выдан не аккредитованным УЦ/не доверенным УЦ");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("B0F9ACD0462519F72D1A241E1D665704F62C7500A9142620FB3FDE551C47A6D2"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректный сертификат

    @Test
    public void verifyBadSignatureCertificate() throws IOException {
        VerificationResult verificationResult = client.verifyCertificate(Common.readFromFile("data/IS_GUTS_2016_1 Некорректный.cer"));

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "У одного из сертификатов в цепочке некорректная подпись");
    }

    @Test
    public void verifyBadSignatureCertificateWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCertificateWithReport(Common.readFromFile("data/IS_GUTS_2016_1 Некорректный.cer"));

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "У одного из сертификатов в цепочке некорректная подпись");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подлинность сертификата НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("CertStatus=\"У одного из сертификатов в цепочке некорректная подпись"));
    }

    @Test
    public void verifyBadSignatureCertificateWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCertificateWithSignedReport(Common.readFromFile("data/IS_GUTS_2016_1 Некорректный.cer"));

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "У одного из сертификатов в цепочке некорректная подпись");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("E0532E7379888EBD76993B8F120E60BA60F392C54868C62A437909BC3EF4DA7E"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Просроченный сертификат

    @Test
    public void verifyBadSignature1Certificate() throws IOException {
        VerificationResult verificationResult = client.verifyCertificate(Common.readFromFile("data/Некорректный сертификат КриптоПро.cer"));

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 5);
        Assert.assertEquals(verificationResult.getDescription(), "Срок действия одного из сертификатов цепочки истек или еще не наступил");
    }

    @Test
    public void verifyBadSignature1CertificateWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCertificateWithReport(Common.readFromFile("data/Некорректный сертификат КриптоПро.cer"));

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 5);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Срок действия одного из сертификатов цепочки истек или еще не наступил");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подлинность сертификата НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Срок действия одного из сертификатов цепочки истек или еще не наступил"));
    }

    @Test
    public void verifyBadSignature1CertificateWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCertificateWithSignedReport(Common.readFromFile("data/Некорректный сертификат КриптоПро.cer"));

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 5);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Срок действия одного из сертификатов цепочки истек или еще не наступил");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
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

    @Test
    public void verifyCMSfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyCMSSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyCMSSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

// Корректная подпись true

    @Test
    public void verifyCMStrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyCMSSignature1WithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyCMSSignature1WithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test
    public void verifyBadSignatureCMSfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS Некорректный.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verifyBadSignatureCMSSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS Некорректный.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyBadSignatureCMSSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS Некорректный.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verifyBadSignatureCMStrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS Некорректный.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verifyBadSignature1CMSSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyBadSignature1CMSSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись1 false

    @Test
    public void verifyBadSignatureCMSfalse1() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS Некорректный1.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 1);
        Assert.assertEquals(verificationResult.getDescription(), "Внутренняя ошибка");
    }

    @Test
    public void verifyBadSignatureCMSSignature1WithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS Некорректный1.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Внутренняя ошибка");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("The hash value is not correct"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyBadSignatureCMSSignature1WithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS Некорректный1.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Внутренняя ошибка");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись1 true

    @Test
    public void verifyBadSignatureCMStrue1() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CMS Некорректный1.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 1);
        Assert.assertEquals(verificationResult.getDescription(), "Внутренняя ошибка");
    }

    @Test
    public void verifyBadSignature1CMSSignature1WithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS Некорректный1.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Внутренняя ошибка");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("The hash value is not correct"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyBadSignature1CMSSignature1WithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CMS Некорректный1.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Внутренняя ошибка");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

                                                            /* CMS Detached */

//Корректная подпись false


    @Test
    public void verifyCMSDetachedfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureDetached(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached.jpg"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyCMSSignatureDetachedWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureDetachedWithReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached.jpg"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyCMSSignature1DetachedWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached.jpg"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test
    public void verifyCMSDetachedtrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureDetached(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached.jpg"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyCMSSignature1DetachedWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureDetachedWithReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached.jpg"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    /*@Test
    public void verifyCMSSignatureDetachedWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached.jpg"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));
    }*/

    @Test
    public void verifyCMSSignatureDetachedWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached.jpg"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test
    public void verifyBadSignatureCMSDetachedfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureDetached(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached1.jpg"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verifyBadSignatureCMSSignature1DetachedWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureDetachedWithReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached1.jpg"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyBadSignatureCMSSignatureDetachedWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached1.jpg"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verifyBadSignatureCMSDetachedtrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureDetached(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached1.jpg"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verifyBadSignature1CMSSignature1DetachedWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureDetachedWithReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached1.jpg"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyBadSignature1CMSSignatureDetachedWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS Detached1.jpg"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

                                                            /* CMS Detached By Hash */

//Корректная подпись false

    @Test
    public void verifyCMSDetachedByHashfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureByHash(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyCMSSignatureByHashWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureByHashWithReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    /*@Test
    public void verifyCMSSignatureByHashWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureByHashWithSignedReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));
    }*/

    @Test
    public void verifyCMSSignatureByHashWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureByHashWithSignedReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test
    public void verifyCMSDetachedByHashtrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureByHash(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyCMSSignature1ByHashWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureByHashWithReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyCMSSignature1ByHashWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureByHashWithSignedReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test
    public void verifyBadSignatureCMSDetachedByHashfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureByHash(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash Некорректный.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verifyBadSignatureCMSSignatureByHashWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureByHashWithReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash Некорректный.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyBadSignatureCMSSignatureByHashWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureByHashWithSignedReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash Некорректный.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verifyBadSignatureCMSDetachedByHashtrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureByHash(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash Некорректный.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verifyBadSignature1CMSSignatureByHashWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureByHashWithReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyBadSignature1CMSSignatureByHashWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureByHashWithSignedReport(Common.readFromFile("data/CMS Detached.sig"), Common.readFromFile("data/CMS By Hash Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

                                                            /* Timestamp */

//Корректный false

    @Test
    public void verifyTimeStampfalse() throws IOException {
        VerificationResult verificationResult = client.verifyTimeStamp(Common.readFromFile("data/1Timestamp.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyTimeStampWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyTimeStampWithReport(Common.readFromFile("data/1Timestamp.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyTimeStampWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyTimeStampWithSignedReport(Common.readFromFile("data/1Timestamp.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Статус подписи: </span>действительна</p>"));
        Assert.assertTrue(report.contains("ВЕРЕН"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректный true

    @Test
    public void verifyTimeStamptrue() throws IOException {
        VerificationResult verificationResult = client.verifyTimeStamp(Common.readFromFile("data/1Timestamp.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verify1TimeStampWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyTimeStampWithReport(Common.readFromFile("data/1Timestamp.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1TimeStampWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyTimeStampWithSignedReport(Common.readFromFile("data/1Timestamp.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Статус подписи: </span>действительна</p>"));
        Assert.assertTrue(report.contains("ВЕРЕН"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректный false

    @Test
    public void verifyBadSignatureTimeStampfalse() throws IOException {
        VerificationResult verificationResult = client.verifyTimeStamp(Common.readFromFile("data/1Timestamp Некорректный.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 2);
        Assert.assertEquals(verificationResult.getDescription(), "Входные данные не являются подписанным сообщением");
    }

    @Test
    public void verifyBadSignatureTimeStampWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyTimeStampWithReport(Common.readFromFile("data/1Timestamp Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 2);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Входные данные не являются подписанным сообщением");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        //Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyBadSignatureTimeStampWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyTimeStampWithSignedReport(Common.readFromFile("data/1Timestamp Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 2);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Входные данные не являются подписанным сообщением");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Входные данные не являются подписанным сообщением"));
        Assert.assertTrue(report.contains("НЕ ВЕРЕН"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректный true

    @Test
    public void verify1BadSignatureTimeStamptrue() throws IOException {
        VerificationResult verificationResult = client.verifyTimeStamp(Common.readFromFile("data/1Timestamp Некорректный.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 2);
        Assert.assertEquals(verificationResult.getDescription(), "Входные данные не являются подписанным сообщением");
    }

    @Test
    public void verify1BadSignatureTimeStampWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyTimeStampWithReport(Common.readFromFile("data/1Timestamp Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 2);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Входные данные не являются подписанным сообщением");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        //Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1BadSignatureTimeStampWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyTimeStampWithSignedReport(Common.readFromFile("data/1Timestamp Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 2);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Входные данные не являются подписанным сообщением");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Входные данные не являются подписанным сообщением"));
        Assert.assertTrue(report.contains("НЕ ВЕРЕН"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

                                                            /* XAdES */

//Корректная подпись false

    @Test
    public void verifyXAdESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyXAdES(Common.readFromFile("data/XAdES.xml"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyXAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyXAdESWithReport(Common.readFromFile("data/XAdES.xml"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyXAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyXAdESWithSignedReport(Common.readFromFile("data/XAdES.xml"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test
    public void verifyXAdEStrue() throws IOException {
        VerificationResult verificationResult = client.verifyXAdES(Common.readFromFile("data/XAdES.xml"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verify1XAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyXAdESWithReport(Common.readFromFile("data/XAdES.xml"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1XAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyXAdESWithSignedReport(Common.readFromFile("data/XAdES.xml"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test
    public void verifyBadSignatureXAdESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyXAdES(Common.readFromFile("data/XAdES Некорректный.xml"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verifyBadSignatureXAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyXAdESWithReport(Common.readFromFile("data/XAdES Некорректный.xml"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyBadSignatureXAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyXAdESWithSignedReport(Common.readFromFile("data/XAdES Некорректный.xml"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verifyBadSignatureXAdEStrue() throws IOException {
        VerificationResult verificationResult = client.verifyXAdES(Common.readFromFile("data/XAdES Некорректный.xml"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verify1BadSignatureXAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyXAdESWithReport(Common.readFromFile("data/XAdES Некорректный.xml"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1BadSignatureXAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyXAdESWithSignedReport(Common.readFromFile("data/XAdES Некорректный.xml"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

                                                            /* XMLDSig */

//Корректная подпись false

    @Test
    public void verifyXMLSignaturefalse() throws IOException {
        VerificationResult verificationResult = client.verifyXMLSignature(Common.readFromFile("data/XMLDSig.xml"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyXMLSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyXMLSignatureWithReport(Common.readFromFile("data/XMLDSig.xml"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyXMLSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyXMLSignatureWithSignedReport(Common.readFromFile("data/XMLDSig.xml"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test
    public void verifyXMLSignaturetrue() throws IOException {
        VerificationResult verificationResult = client.verifyXMLSignature(Common.readFromFile("data/XMLDSig.xml"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verify1XMLSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyXMLSignatureWithReport(Common.readFromFile("data/XMLDSig.xml"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1XMLSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyXMLSignatureWithSignedReport(Common.readFromFile("data/XMLDSig.xml"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test
    public void verifyBadSignatureXMLSignaturefalse() throws IOException {
        VerificationResult verificationResult = client.verifyXMLSignature(Common.readFromFile("data/XMLDSig Некорректный.xml"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verifyBadSignatureXMLSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyXMLSignatureWithReport(Common.readFromFile("data/XMLDSig Некорректный.xml"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyBadSignatureXMLSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyXMLSignatureWithSignedReport(Common.readFromFile("data/XMLDSig Некорректный.xml"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verifyBadSignatureXMLSignaturetrue() throws IOException {
        VerificationResult verificationResult = client.verifyXMLSignature(Common.readFromFile("data/XMLDSig Некорректный.xml"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verify1BadSignatureXMLSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyXMLSignatureWithReport(Common.readFromFile("data/XMLDSig Некорректный.xml"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1BadSignatureXMLSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyXMLSignatureWithSignedReport(Common.readFromFile("data/XMLDSig Некорректный.xml"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

                                                            /* PAdES */

//Корректная подпись false

    @Test
    public void verifyPAdESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyPAdES(Common.readFromFile("data/PAdES.pdf"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyPAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyPAdESWithReport(Common.readFromFile("data/PAdES.pdf"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyPAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyPAdESWithSignedReport(Common.readFromFile("data/PAdES.pdf"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test
    public void verifyPAdEStrue() throws IOException {
        VerificationResult verificationResult = client.verifyPAdES(Common.readFromFile("data/PAdES.pdf"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verify1PAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyPAdESWithReport(Common.readFromFile("data/PAdES.pdf"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1PAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyPAdESWithSignedReport(Common.readFromFile("data/PAdES.pdf"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test
    public void verifyBadSignaturePAdESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyPAdES(Common.readFromFile("data/PAdES Некорректный.pdf"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись неверна");
    }

    @Test
    public void verifyBadSignaturePAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyPAdESWithReport(Common.readFromFile("data/PAdES Некорректный.pdf"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись неверна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyBadSignaturePAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyPAdESWithSignedReport(Common.readFromFile("data/PAdES Некорректный.pdf"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись неверна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verifyBadSignaturePAdEStrue() throws IOException {
        VerificationResult verificationResult = client.verifyPAdES(Common.readFromFile("data/PAdES Некорректный.pdf"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись неверна");
    }

    @Test
    public void verify1BadSignaturePAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyPAdESWithReport(Common.readFromFile("data/PAdES Некорректный.pdf"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись неверна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1BadSignaturePAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyPAdESWithSignedReport(Common.readFromFile("data/PAdES Некорректный.pdf"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись неверна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

                                                            /* CAdES */

//Корректная подпись false

    @Test
    public void verifyCAdESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyCAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyCAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test
    public void verifyCAdEStrue() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verify1CAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1CAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test
    public void verifyBadSignatureCAdESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES Некорректный.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись неверна");
    }

    @Test
    public void verifyBadSignatureCAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES Некорректный.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись неверна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyBadSignatureCAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES Некорректный.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись неверна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verifyBadSignatureCAdEStrue() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES Некорректный.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись неверна");
    }

    @Test
    public void verify1BadSignatureCAdESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись неверна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1BadSignatureCAdESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES Некорректный.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись неверна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//CAdES-BES

//Корректная подпись false

        @Test
        public void verifyCAdESBESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES-BES Корректная основная подпись.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

        @Test
        public void verifyCAdESBESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES-BES Корректная основная подпись.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyCAdESBESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES-BES Корректная основная подпись.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>0<div style=\"padding-left: 10px; font-size: smaller;\">ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }


                                                            /* WS-Security */

//Корректная подпись false

    @Test
    public void verifyWSSSignaturefalse() throws IOException {
        VerificationResult verificationResult = client.verifyWSSSignature(Common.readFromFile("data/WS-Security.xml"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyWSSSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyWSSSignatureWithReport(Common.readFromFile("data/WS-Security.xml"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
    }

    @Test
    public void verifyWSSSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyWSSSignatureWithSignedReport(Common.readFromFile("data/WS-Security.xml"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test
    public void verifyWSSSignaturetrue() throws IOException {
        VerificationResult verificationResult = client.verifyWSSSignature(Common.readFromFile("data/WS-Security.xml"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verify1WSSSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyWSSSignatureWithReport(Common.readFromFile("data/WS-Security.xml"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    /*@Test
    public void verifyWSSSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyWSSSignatureWithReport(Common.readFromFile("data/WS-Security.xml"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }*/

    /*@Test
    public void verifyWSSSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyWSSSignatureWithSignedReport(Common.readFromFile("data/WS-Security.xml"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }*/

    @Test
    public void verify1WSSSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyWSSSignatureWithSignedReport(Common.readFromFile("data/WS-Security.xml"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись действительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись верна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    /*@Test
    public void verifyWSSSignaturetrue() throws IOException {
        VerificationResult verificationResult = client.verifyWSSSignature(Common.readFromFile("data/WS-Security.xml"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }*/

//Некорректная подпись false

    @Test
    public void verifyBadSignatureWSSSignaturefalse() throws IOException {
        VerificationResult verificationResult = client.verifyWSSSignature(Common.readFromFile("data/WS-Security Некорректный.xml"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verifyBadSignatureWSSSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyWSSSignatureWithReport(Common.readFromFile("data/WS-Security Некорректный.xml"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyBadSignatureWSSSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyWSSSignatureWithSignedReport(Common.readFromFile("data/WS-Security Некорректный.xml"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verifyBadSignatureWSSSignaturetrue() throws IOException {
        VerificationResult verificationResult = client.verifyWSSSignature(Common.readFromFile("data/WS-Security Некорректный.xml"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись недействительна");
    }

    @Test
    public void verify1BadSignatureWSSSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyWSSSignatureWithReport(Common.readFromFile("data/WS-Security Некорректный.xml"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись недействительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1BadSignatureWSSSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyWSSSignatureWithSignedReport(Common.readFromFile("data/WS-Security Некорректный.xml"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Электронная подпись недействительна");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
        Assert.assertTrue(report.contains("Не проверялся"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyCMSwithReportfalse() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CMS.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));

    }
}
