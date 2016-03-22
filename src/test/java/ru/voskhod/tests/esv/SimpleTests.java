package ru.voskhod.tests.esv;


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

    //TODO логирование тел сообщений на уровне trace: logger.trace
    //TODO добавить description
    //TODO обновить testng.xml

    @Test (description = "GUTS-ESV1: Проверка сертификата")
     public void verifyCertificate() throws IOException {
        VerificationResult verificationResult = client.verifyCertificate(Common.readFromFile("data/IS_GUTS_2016_1.cer"));

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром");
    }

    @Test (description = "GUTS-ESV2: Проверка сертификата с отчетом")
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

//Revoked сертификат аккредитованного УЦ

    @Test
    public void verifyRevokedCertificate() throws IOException {
        VerificationResult verificationResult = client.verifyCertificate(Common.readFromFile("data/IS_GUTS_2016_2.cer"));

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 7);
        Assert.assertEquals(verificationResult.getDescription(), "Один из сертификатов цепочки аннулирован");
    }

    @Test
    public void verifyRevokedCertificateWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCertificateWithReport(Common.readFromFile("data/IS_GUTS_2016_2.cer"));

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 7);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Один из сертификатов цепочки аннулирован");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подлинность сертификата НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("<State>The certificate is revoked"));
    }

    @Test
    public void verifyRevokedCertificateWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCertificateWithSignedReport(Common.readFromFile("data/IS_GUTS_2016_2.cer"));

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 7);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Один из сертификатов цепочки аннулирован");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕ ПОДТВЕРЖДЕНА"));
        Assert.assertTrue(report.contains("The certificate is revoked."));
        Assert.assertTrue(report.contains("5D3510032619F4C5183D1C1418B9F4C61C71B444F7CC115F0DA415CB2BA70D98"));

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
        Assert.assertTrue(report.contains("24F840E895E54D6074CFE9C57C83D8DEA438E1BDE78643FC5D5C1A08CC2644CC"));

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
        Assert.assertTrue(report.contains("24F840E895E54D6074CFE9C57C83D8DEA438E1BDE78643FC5D5C1A08CC2644CC"));

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
        Assert.assertTrue(report.contains("E49D91384135F865419F4C88275D89591C3D61140B74279D0C7D11E004D0394E"));

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
        Assert.assertTrue(report.contains("E49D91384135F865419F4C88275D89591C3D61140B74279D0C7D11E004D0394E"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись Revoked false

    //Некорректная подпись false

    @Test
    public void verifyRevokedSignatureCMSfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CAdES-BES 2.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(),13);
        Assert.assertEquals(verificationResult.getDescription(), "Сертификат подписи недействителен");
    }

    @Test
    public void verifyRevokedSignatureCMSSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CAdES-BES 2.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 13);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Сертификат подписи недействителен");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Один из сертификатов цепочки аннулирован"));
    }

    @Test
    public void verifyRevokedSignatureCMSSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CAdES-BES 2.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 13);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Сертификат подписи недействителен");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(reportBytes);
        String signature = StringUtils.newStringUtf8(signatureBytes);


        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Один из сертификатов цепочки аннулирован"));
        Assert.assertTrue(report.contains("23AE6AEE743EAAD6305525634F543E3FAC08A293108107EB0172989F7C824CA4"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись Revoked true

    @Test
    public void verifyRevokedSignatureCMStrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignature(Common.readFromFile("data/CAdES-BES 2.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyRevokedSignature1CMSSignatureWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureWithReport(Common.readFromFile("data/CAdES-BES 2.sig"), true);

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
    public void verifyRevokedSignature1CMSSignatureWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureWithSignedReport(Common.readFromFile("data/CAdES-BES 2.sig"), true);

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
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("23AE6AEE743EAAD6305525634F543E3FAC08A293108107EB0172989F7C824CA4"));

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
        Assert.assertTrue(report.contains("DEBECBC7767EA33912B531435590CAB3F1132E43DF41A2E5002FFF709EF63921"));

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
        Assert.assertTrue(report.contains("DEBECBC7767EA33912B531435590CAB3F1132E43DF41A2E5002FFF709EF63921"));

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
        Assert.assertTrue(report.contains("377CDF28C8D1B78AAAFD7A53B32C3DBDC698B8D254BD3757E20DDB4C5F0B8544"));

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
        Assert.assertTrue(report.contains("377CDF28C8D1B78AAAFD7A53B32C3DBDC698B8D254BD3757E20DDB4C5F0B8544"));

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
        Assert.assertTrue(report.contains("377CDF28C8D1B78AAAFD7A53B32C3DBDC698B8D254BD3757E20DDB4C5F0B8544"));

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
        Assert.assertTrue(report.contains("377CDF28C8D1B78AAAFD7A53B32C3DBDC698B8D254BD3757E20DDB4C5F0B8544"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись Revoked

    //Некорректная подпись false

    @Test
    public void verifyRevokedSignatureCMSDetachedfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureDetached(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS Detached.jpg"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 13);
        Assert.assertEquals(verificationResult.getDescription(), "Сертификат подписи недействителен");
    }

    @Test
    public void verifyRevokedSignatureCMSSignature1DetachedWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureDetachedWithReport(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS Detached.jpg"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 13);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Сертификат подписи недействителен");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Один из сертификатов цепочки аннулирован"));
    }

    @Test
    public void verifyRevokedSignatureCMSSignatureDetachedWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS Detached.jpg"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 13);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Сертификат подписи недействителен");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Один из сертификатов цепочки аннулирован"));
        Assert.assertTrue(report.contains("B2C61567AF4B961D83EE668D9D65D891EA262FF67ABA51F3625795137E78CA9C"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verifyRevokedSignatureCMSDetachedtrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureDetached(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS Detached.jpg"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyRevokedSignature1CMSSignature1DetachedWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureDetachedWithReport(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS Detached.jpg"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyRevokedSignature1CMSSignatureDetachedWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureDetachedWithSignedReport(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS Detached.jpg"), true);

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
        Assert.assertTrue(report.contains("B2C61567AF4B961D83EE668D9D65D891EA262FF67ABA51F3625795137E78CA9C"));

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
        Assert.assertTrue(report.contains("377CDF28C8D1B78AAAFD7A53B32C3DBDC698B8D254BD3757E20DDB4C5F0B8544"));

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
        Assert.assertTrue(report.contains("377CDF28C8D1B78AAAFD7A53B32C3DBDC698B8D254BD3757E20DDB4C5F0B8544"));

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
        Assert.assertTrue(report.contains("377CDF28C8D1B78AAAFD7A53B32C3DBDC698B8D254BD3757E20DDB4C5F0B8544"));

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
        Assert.assertTrue(report.contains("377CDF28C8D1B78AAAFD7A53B32C3DBDC698B8D254BD3757E20DDB4C5F0B8544"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись Revoked

    //Некорректная подпись false

    @Test
    public void verifyRevokedSignatureCMSDetachedByHashfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureByHash(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS By Hash.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 13);
        Assert.assertEquals(verificationResult.getDescription(), "Сертификат подписи недействителен");
    }

    @Test
    public void verifyRevokedSignatureCMSSignatureByHashWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureByHashWithReport(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS By Hash.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 13);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Сертификат подписи недействителен");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Один из сертификатов цепочки аннулирован"));
    }

    @Test
    public void verifyRevokedSignatureCMSSignatureByHashWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureByHashWithSignedReport(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS By Hash.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(),13);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Сертификат подписи недействителен");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Один из сертификатов цепочки аннулирован"));
        Assert.assertTrue(report.contains("B2C61567AF4B961D83EE668D9D65D891EA262FF67ABA51F3625795137E78CA9C"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verifyRevokedSignatureCMSDetachedByHashtrue() throws IOException {
        VerificationResult verificationResult = client.verifyCMSSignatureByHash(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS By Hash.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyRevokedSignature1CMSSignatureByHashWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCMSSignatureByHashWithReport(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS By Hash.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 0);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись действительна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verifyRevokedSignature1CMSSignatureByHashWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCMSSignatureByHashWithSignedReport(Common.readFromFile("data/CMS Detached 2.sig"), Common.readFromFile("data/CMS By Hash.sig"), true);

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
        Assert.assertTrue(report.contains("B2C61567AF4B961D83EE668D9D65D891EA262FF67ABA51F3625795137E78CA9C"));

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
        Assert.assertTrue(report.contains("0E2122824C274101BFC2FED35A42F13AEC3BE297C3B69626BCD3D32058084E4C"));

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
        Assert.assertTrue(report.contains("0E2122824C274101BFC2FED35A42F13AEC3BE297C3B69626BCD3D32058084E4C"));

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
        Assert.assertTrue(report.contains("93F5486B8D17F58B95F6EE2CA42F923F93BEE1998E7F41766E1A3FFA51AE872A"));

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
        Assert.assertTrue(report.contains("93F5486B8D17F58B95F6EE2CA42F923F93BEE1998E7F41766E1A3FFA51AE872A"));

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
        Assert.assertTrue(report.contains("87AFCFD8E7E0FA97DF390FF4BF3D2BF1AD2C8454841BC2E9A44941349EEEC8CE"));

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
        Assert.assertTrue(report.contains("87AFCFD8E7E0FA97DF390FF4BF3D2BF1AD2C8454841BC2E9A44941349EEEC8CE"));

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
        Assert.assertTrue(report.contains("FE449030C72DD4745BEB254541FDF504264F6BC9B64F1091F5E828EBB540065A"));

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
        Assert.assertTrue(report.contains("FE449030C72DD4745BEB254541FDF504264F6BC9B64F1091F5E828EBB540065A"));

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
        Assert.assertTrue(report.contains("87AFCFD8E7E0FA97DF390FF4BF3D2BF1AD2C8454841BC2E9A44941349EEEC8CE"));

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
        Assert.assertTrue(report.contains("87AFCFD8E7E0FA97DF390FF4BF3D2BF1AD2C8454841BC2E9A44941349EEEC8CE"));

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
        Assert.assertTrue(report.contains("FE449030C72DD4745BEB254541FDF504264F6BC9B64F1091F5E828EBB540065A"));

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
        Assert.assertTrue(report.contains("FE449030C72DD4745BEB254541FDF504264F6BC9B64F1091F5E828EBB540065A"));

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
        Assert.assertTrue(report.contains("A8EE01D79F9C799D23758000376BAC18637C6DEFF6350178CF0144F242A3F6FD"));

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
        Assert.assertTrue(report.contains("A8EE01D79F9C799D23758000376BAC18637C6DEFF6350178CF0144F242A3F6FD"));

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
        Assert.assertTrue(report.contains("A4A6B771EF412CE24824822A9A5984F8EDE1360C14B1D5BDB9B11B52A4B9C823"));

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
        Assert.assertTrue(report.contains("A4A6B771EF412CE24824822A9A5984F8EDE1360C14B1D5BDB9B11B52A4B9C823"));

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
        Assert.assertTrue(report.contains("23DA65528F0E0AE171BA0D76BDFD064D1056CC598BEBB80954F3CE63161752D8"));

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
        Assert.assertTrue(report.contains("23DA65528F0E0AE171BA0D76BDFD064D1056CC598BEBB80954F3CE63161752D8"));

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
        Assert.assertTrue(report.contains("A7AE8E44FB0689283D4F7F5227F6C6343FD78C6D223B91C0268E7D37B8A89806"));

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
        Assert.assertTrue(report.contains("A7AE8E44FB0689283D4F7F5227F6C6343FD78C6D223B91C0268E7D37B8A89806"));

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
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-BES.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
        public void verifyCAdESBESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-BES.sig"), false);

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
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-BES.sig"), false);

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
        Assert.assertTrue(report.contains("75F23873DE58DA628E1CEA2EAB95F39A3C83B7A2808CC2A7B992CAF9757140FD"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test
    public void verify1CAdESBESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-BES.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verify1CAdESBESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-BES.sig"), true);

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
    public void verify1CAdESBESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-BES.sig"), true);

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
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>-1<div style=\"padding-left: 10px; font-size: smaller;\">Не проверялся"));
        Assert.assertTrue(report.contains("75F23873DE58DA628E1CEA2EAB95F39A3C83B7A2808CC2A7B992CAF9757140FD"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test
    public void verifyBadSignatureCAdESBESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-BES.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись неверна");
    }

    @Test
    public void verifyBadSignatureCAdESBESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-BES.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись неверна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
        Assert.assertTrue(report.contains("Сообщение содержит неверную подпись"));
    }

    @Test
    public void verifyBadSignatureCAdESBESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-BES.sig"), false);

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
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>0<div style=\"padding-left: 10px; font-size: smaller;\">ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
        Assert.assertTrue(report.contains("200074E4DCF2384F54B9E8741C4FDB6438C80BDDC05CD97848EEB1DFDD288953"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verify1BadSignatureCAdESBESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-BES.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись неверна");
    }

    @Test
    public void verify1BadSignatureCAdESBESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-BES.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись неверна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
        Assert.assertTrue(report.contains("Сообщение содержит неверную подпись"));
    }

    @Test
    public void verify1BadSignatureCAdESBESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-BES.sig"), true);

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
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>-1<div style=\"padding-left: 10px; font-size: smaller;\">Не проверялся"));
        Assert.assertTrue(report.contains("200074E4DCF2384F54B9E8741C4FDB6438C80BDDC05CD97848EEB1DFDD288953"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//CAdES-A 2ATSv3

    //Корректная подпись false

    @Test
    public void verifyCAdESATSv3false() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-XL 2ATSv3.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyCAdESATSv3WithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-XL 2ATSv3.sig"), false);

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
    public void verifyCAdESATSv3WithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-XL 2ATSv3.sig"), false);

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
        Assert.assertTrue(report.contains("Дата создания атрибута / ответа от TSA: </span>2016.03.22 11:38:53"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>0<div style=\"padding-left: 10px; font-size: smaller;\">ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
        Assert.assertTrue(report.contains("E4FC9C045B1FA2F88F997B64CEF62307020386F51A9BF6890F1D8EBE529AAF9A"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test
    public void verify1CAdESATSv3false() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-XL 2ATSv3.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verify1CAdESATSv3WithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-XL 2ATSv3.sig"), true);

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
    public void verify1CAdESATSv3WithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A CAdES-XL 2ATSv3.sig"), true);

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
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Дата создания атрибута / ответа от TSA: </span>2016.03.22 11:38:53"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>-1<div style=\"padding-left: 10px; font-size: smaller;\">Не проверялся"));
        Assert.assertTrue(report.contains("E4FC9C045B1FA2F88F997B64CEF62307020386F51A9BF6890F1D8EBE529AAF9A"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test
    public void verifyBadSignatureCAdESATSv3false() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-XL 2ATSv3.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись неверна");
    }

    @Test
    public void verifyBadSignatureCAdESATSv3WithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-XL 2ATSv3.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись неверна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("Сообщение содержит неверную подпись"));
    }

    @Test
    public void verifyBadSignatureCAdESATSv3WithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-XL 2ATSv3.sig"), false);

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
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Действителен"));
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Дата создания атрибута / ответа от TSA: </span>2016.03.22 12:01:44"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>0<div style=\"padding-left: 10px; font-size: smaller;\">ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
        Assert.assertTrue(report.contains("99726260C645D35699F9385C420A630FA8B2867546F5216DCC57AEF03EA6FF78"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verify1BadSignatureCAdESATSv3false() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-XL 2ATSv3.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись неверна");
    }

    @Test
    public void verify1BadSignatureCAdESATSv3WithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-XL 2ATSv3.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись неверна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1BadSignatureCAdESATSv3WithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/Тестирование ИС ГУЦ КриптоПро CAdES-A Некорректная подпись CAdES-XL 2ATSv3.sig"), true);

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
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Дата создания атрибута / ответа от TSA: </span>2016.03.22 12:01:44"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>-1<div style=\"padding-left: 10px; font-size: smaller;\">Не проверялся"));
        Assert.assertTrue(report.contains("99726260C645D35699F9385C420A630FA8B2867546F5216DCC57AEF03EA6FF78"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }
/*
//CAdES-A Revoked ATSv3

    //Корректная подпись false

    @Test
    public void verifyRevokedCAdESBESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES-BES Корректная основная подпись Revoked ATS.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 13);
        Assert.assertEquals(verificationResult.getDescription(), "Сертификат подписи недействителен");
    }

    @Test
    public void verifyRevokedCAdESBESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES-BES Корректная основная подпись Revoked ATS.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 13);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Сертификат подписи недействителен");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Один из сертификатов цепочки аннулирован"));
    }

    @Test
    public void verifyRevokedCAdESBESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES-BES Корректная основная подпись Revoked ATS.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 13);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Сертификат подписи недействителен");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Один из сертификатов цепочки аннулирован"));
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>7<div style=\"padding-left: 10px; font-size: smaller;\">Один из сертификатов цепочки аннулирован"));
        Assert.assertTrue(report.contains("586EC868A8665421D3DC7C82393338F2126B48D140C5AA518923DF7A8C15E73D"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test
    public void verify1RevokedCAdESBESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES-BES Корректная основная подпись Revoked ATS.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verify1RevokedCAdESBESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES-BES Корректная основная подпись Revoked ATS.sig"), true);

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
    public void verify1RevokedCAdESBESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES-BES Корректная основная подпись Revoked ATS.sig"), true);

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
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>-1<div style=\"padding-left: 10px; font-size: smaller;\">Не проверялся"));
        Assert.assertTrue(report.contains("586EC868A8665421D3DC7C82393338F2126B48D140C5AA518923DF7A8C15E73D"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test
    public void verifyBadSignatureRevokedCAdESBESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES-BES Некорректная основная подпись Revoked ATS.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 1);
        Assert.assertEquals(verificationResult.getDescription(), "Внутренняя ошибка");
    }

    @Test
    public void verifyBadSignatureRevokedCAdESBESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES-BES Некорректная основная подпись Revoked ATS.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Внутренняя ошибка");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
        Assert.assertTrue(report.contains("The hash value is not correct"));
    }

    @Test
    public void verifyBadSignatureRevokedCAdESBESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES-BES Некорректная основная подпись Revoked ATS.sig"), false);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Внутренняя ошибка");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Внутренняя ошибка"));
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>7<div style=\"padding-left: 10px; font-size: smaller;\">Один из сертификатов цепочки аннулирован"));
        Assert.assertTrue(report.contains("355D5C825BFEB2071C4256A558B6A133213FF2B782D16FAB825394989C393F4B"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verify1BadSignatureRevokedCAdESBESfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES-BES Некорректная основная подпись Revoked ATS.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 1);
        Assert.assertEquals(verificationResult.getDescription(), "Внутренняя ошибка");
    }

    @Test
    public void verify1BadSignatureRevokedCAdESBESWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES-BES Некорректная основная подпись Revoked ATS.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Внутренняя ошибка");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1BadSignatureRevokedCAdESBESWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES-BES Некорректная основная подпись Revoked ATS.sig"), true);

        logger.info("code: " + verificationResultWithSignedReport.getCode());
        logger.info("desc: " + verificationResultWithSignedReport.getDescription());
        Assert.assertEquals(verificationResultWithSignedReport.getCode(), 1);
        Assert.assertEquals(verificationResultWithSignedReport.getDescription(), "Внутренняя ошибка");
        byte[] reportBytes = verificationResultWithSignedReport.getReport();
        byte[] signatureBytes = verificationResultWithSignedReport.getSignature();
        String report = StringUtils.newStringUtf8(verificationResultWithSignedReport.getReport());
        String signature = StringUtils.newStringUtf8(signatureBytes);

        logger.info("repstr: " + report);
        logger.info("signstr: " + signature);
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>-1<div style=\"padding-left: 10px; font-size: smaller;\">Не проверялся"));
        Assert.assertTrue(report.contains("355D5C825BFEB2071C4256A558B6A133213FF2B782D16FAB825394989C393F4B"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }
*/

//CAdES-XL

    //Корректная подпись false

    @Test
    public void verifyCAdESXLfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES-XL КриптоПро Корректная основная подпись.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verifyCAdESXLWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES-XL КриптоПро Корректная основная подпись.sig"), false);

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
    public void verifyCAdESXLWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES-XL КриптоПро Корректная основная подпись.sig"), false);

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
        Assert.assertTrue(report.contains("66FEA04D3DE3230CE62B9572B4A3E316EA5BC65D6328E41F8151AB348A372A88"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Корректная подпись true

    @Test
    public void verify1CAdESXLfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES-XL КриптоПро Корректная основная подпись.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

    @Test
    public void verify1CAdESXLWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES-XL КриптоПро Корректная основная подпись.sig"), true);

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
    public void verify1CAdESXLWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES-XL КриптоПро Корректная основная подпись.sig"), true);

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
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>-1<div style=\"padding-left: 10px; font-size: smaller;\">Не проверялся"));
        Assert.assertTrue(report.contains("66FEA04D3DE3230CE62B9572B4A3E316EA5BC65D6328E41F8151AB348A372A88"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись false

    @Test
    public void verifyBadSignatureCAdESXLfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES-XL КриптоПро Некорректная основная подпись.sig"), false);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись неверна");
    }

    @Test
    public void verifyBadSignatureCAdESXLWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES-XL КриптоПро Некорректная основная подпись.sig"), false);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись неверна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
        Assert.assertTrue(report.contains("Электронная подпись неверна"));
    }

    @Test
    public void verifyBadSignatureCAdESXLWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES-XL КриптоПро Некорректная основная подпись.sig"), false);

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
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        //Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>0<div style=\"padding-left: 10px; font-size: smaller;\">ДЕЙСТВИТЕЛЕН, сертификат выдан аккредитованным удостоверяющим центром"));
        Assert.assertTrue(report.contains("13F1521A7228D66DFA838D09A6749F181F54D1604C8645764F475B4B55C7C0B9"));

        VerificationResult verificationResult = client.verifyCMSSignatureDetached(signatureBytes, reportBytes, true);
        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 0);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись действительна");
    }

//Некорректная подпись true

    @Test
    public void verify1BadSignatureCAdESXLfalse() throws IOException {
        VerificationResult verificationResult = client.verifyCAdES(Common.readFromFile("data/CAdES-XL КриптоПро Некорректная основная подпись.sig"), true);

        logger.info("code: " + verificationResult.getCode());
        logger.info("desc: " + verificationResult.getDescription());
        Assert.assertEquals(verificationResult.getCode(), 3);
        Assert.assertEquals(verificationResult.getDescription(), "Электронная подпись неверна");
    }

    @Test
    public void verify1BadSignatureCAdESXLWithReport() throws IOException, Base64DecodingException {
        VerificationResultWithReport verificationResultWithReport = client.verifyCAdESWithReport(Common.readFromFile("data/CAdES-XL КриптоПро Некорректная основная подпись.sig"), true);

        logger.info("code: " + verificationResultWithReport.getCode());
        logger.info("desc: " + verificationResultWithReport.getDescription());
        Assert.assertEquals(verificationResultWithReport.getCode(), 3);
        Assert.assertEquals(verificationResultWithReport.getDescription(), "Электронная подпись неверна");
        String report = StringUtils.newStringUtf8(verificationResultWithReport.getReport());
        logger.info("repstr: " + report);
        Assert.assertTrue(report.contains("ResultText=\"Подпись НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("CertStatus=\"Не проверялся"));
    }

    @Test
    public void verify1BadSignatureCAdESXLWithSignedReport() throws IOException, Base64DecodingException {
        VerificationResultWithSignedReport verificationResultWithSignedReport = client.verifyCAdESWithSignedReport(Common.readFromFile("data/CAdES-XL КриптоПро Некорректная основная подпись.sig"), true);

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
        Assert.assertTrue(report.contains("НЕДЕЙСТВИТЕЛЬНА"));
        Assert.assertTrue(report.contains("Не проверялся"));
        Assert.assertTrue(report.contains("Найден корректный атрибут CAdES-A v3"));
        Assert.assertTrue(report.contains("Статус сертификата TSA: </span>-1<div style=\"padding-left: 10px; font-size: smaller;\">Не проверялся"));
        Assert.assertTrue(report.contains("13F1521A7228D66DFA838D09A6749F181F54D1604C8645764F475B4B55C7C0B9"));

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
        Assert.assertTrue(report.contains("2D42DCF4E6F7623E4CAF2F35FA9C1D953F7AB2A98EBFDEAA8A626F696D73AA1E"));

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
        Assert.assertTrue(report.contains("2D42DCF4E6F7623E4CAF2F35FA9C1D953F7AB2A98EBFDEAA8A626F696D73AA1E"));

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
        Assert.assertTrue(report.contains("4AF73AA6295B909FCDFEC77E69391DAD9073067E083A5EC3CEB08773C6A37DAF"));

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
        Assert.assertTrue(report.contains("4AF73AA6295B909FCDFEC77E69391DAD9073067E083A5EC3CEB08773C6A37DAF"));

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

