package ru.voskhod.tests.esv;

import org.apache.log4j.Logger;
import ru.rt.server.esv.*;

import java.net.MalformedURLException;
import java.net.URL;

public class Client {

    private static Logger logger = Logger.getLogger(TestBase.class);
    private SignatureToolSoap signatureToolSoap;

    public Client(Config config) throws MalformedURLException {
        SignatureTool signatureTool = new SignatureTool(new URL(config.get("wsdlUrl")));
        signatureToolSoap = signatureTool.getSignatureToolSoap();
    }
/* Certificate */
    public VerificationResult verifyCertificate(byte[] certificate) {
        return signatureToolSoap.verifyCertificate(certificate);
    }

    public VerificationResultWithReport verifyCertificateWithReport(byte[] certificate) {
        return signatureToolSoap.verifyCertificateWithReport(certificate);
    }

    public VerificationResultWithSignedReport verifyCertificateWithSignedReport(byte[] certificate) {
        return signatureToolSoap.verifyCertificateWithSignedReport(certificate);
    }

/* CMS */
    public VerificationResult verifyCMSSignature(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCMSSignature(message, verifySignatureOnly);
    }

    public VerificationResultWithReport verifyCMSSignatureWithReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCMSSignatureWithReport(message, verifySignatureOnly);
    }

    public VerificationResultWithSignedReport verifyCMSSignatureWithSignedReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCMSSignatureWithSignedReport(message, verifySignatureOnly);
    }

/* CMS Detached */
    public VerificationResult verifyCMSSignatureDetached(byte[] message, byte[] originalContent, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCMSSignatureDetached(message, originalContent, verifySignatureOnly);
    }

    public VerificationResultWithReport verifyCMSSignatureDetachedWithReport(byte[] message, byte[] originalContent, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCMSSignatureDetachedWithReport(message, originalContent, verifySignatureOnly);
    }

    public VerificationResultWithSignedReport verifyCMSSignatureDetachedWithSignedReport(byte[] message, byte[] originalContent, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCMSSignatureDetachedWithSignedReport(message, originalContent, verifySignatureOnly);
    }

/* CMS Detached By Hash */
    public VerificationResult verifyCMSSignatureByHash(byte[] message, byte[] hash, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCMSSignatureByHash(message, hash, verifySignatureOnly);
    }

    public VerificationResultWithReport verifyCMSSignatureByHashWithReport(byte[] message, byte[] hash, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCMSSignatureByHashWithReport(message, hash, verifySignatureOnly);
    }

    public VerificationResultWithSignedReport verifyCMSSignatureByHashWithSignedReport(byte[] message, byte[] hash, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCMSSignatureByHashWithSignedReport(message, hash, verifySignatureOnly);
    }

/* XAdES */
    public VerificationResult verifyXAdES(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyXAdES(message, verifySignatureOnly);
    }

    public VerificationResultWithReport verifyXAdESWithReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyXAdESWithReport(message, verifySignatureOnly);
    }

    public VerificationResultWithSignedReport verifyXAdESWithSignedReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyXAdESWithSignedReport(message, verifySignatureOnly);
    }

/* XMLDSig */
    public VerificationResult verifyXMLSignature(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyXMLSignature(message, verifySignatureOnly);
    }

    public VerificationResultWithReport verifyXMLSignatureWithReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyXMLSignatureWithReport(message, verifySignatureOnly);
    }

    public VerificationResultWithSignedReport verifyXMLSignatureWithSignedReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyXMLSignatureWithSignedReport(message, verifySignatureOnly);
    }

/* PAdES */
    public VerificationResult verifyPAdES(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyPAdES(message, verifySignatureOnly);
    }

    public VerificationResultWithReport verifyPAdESWithReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyPAdESWithReport(message, verifySignatureOnly);
    }

    public VerificationResultWithSignedReport verifyPAdESWithSignedReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyPAdESWithSignedReport(message, verifySignatureOnly);
    }

/* Timestamp */
    public VerificationResult verifyTimeStamp(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyTimeStamp(message, verifySignatureOnly);
    }

    public VerificationResultWithReport verifyTimeStampWithReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyTimeStampWithReport(message, verifySignatureOnly);
    }

    public VerificationResultWithSignedReport verifyTimeStampWithSignedReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyTimeStampWithSignedReport(message, verifySignatureOnly);
    }

/* WS-Security */
    public VerificationResult verifyWSSSignature(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyWSSSignature(message, verifySignatureOnly);
    }

    public VerificationResultWithReport verifyWSSSignatureWithReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyWSSSignatureWithReport(message, verifySignatureOnly);
    }

    public VerificationResultWithSignedReport verifyWSSSignatureWithSignedReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyWSSSignatureWithSignedReport(message, verifySignatureOnly);
    }

    /*public VerificationResultWithReport verifyCMSSignatureWithReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCMSSignatureWithReport(message, verifySignatureOnly);
    }*/

    /* CAdES */
    public VerificationResult verifyCAdES(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCAdES(message, verifySignatureOnly);
    }

    public VerificationResultWithReport verifyCAdESWithReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCAdESWithReport(message, verifySignatureOnly);
    }

    public VerificationResultWithSignedReport verifyCAdESWithSignedReport(byte[] message, boolean verifySignatureOnly) {
        return signatureToolSoap.verifyCAdESWithSignedReport(message, verifySignatureOnly);
    }
}
