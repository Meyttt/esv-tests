
package ru.rt.server.esv;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.ws.RequestWrapper;
import javax.xml.ws.ResponseWrapper;


/**
 * This class was generated by the JAX-WS RI.
 * JAX-WS RI 2.2.4-b01
 * Generated source version: 2.2
 * 
 */
@WebService(name = "SignatureToolSoap", targetNamespace = "http://esv.server.rt.ru")
@XmlSeeAlso({
    ObjectFactory.class
})
public interface SignatureToolSoap {


    /**
     * 
     * @param certificate
     * @return
     *     returns ru.rt.server.esv.VerificationResult
     */
    @WebMethod(operationName = "VerifyCertificate", action = "http://esv.server.rt.ru/VerifyCertificate")
    @WebResult(name = "VerifyCertificateResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCertificate", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCertificate")
    @ResponseWrapper(localName = "VerifyCertificateResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCertificateResponse")
    public VerificationResult verifyCertificate(
        @WebParam(name = "certificate", targetNamespace = "http://esv.server.rt.ru")
        byte[] certificate);

    /**
     * 
     * @param certificate
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithReport
     */
    @WebMethod(operationName = "VerifyCertificateWithReport", action = "http://esv.server.rt.ru/VerifyCertificateWithReport")
    @WebResult(name = "VerifyCertificateWithReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCertificateWithReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCertificateWithReport")
    @ResponseWrapper(localName = "VerifyCertificateWithReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCertificateWithReportResponse")
    public VerificationResultWithReport verifyCertificateWithReport(
        @WebParam(name = "certificate", targetNamespace = "http://esv.server.rt.ru")
        byte[] certificate);

    /**
     * 
     * @param certificate
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithSignedReport
     */
    @WebMethod(operationName = "VerifyCertificateWithSignedReport", action = "http://esv.server.rt.ru/VerifyCertificateWithSignedReport")
    @WebResult(name = "VerifyCertificateWithSignedReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCertificateWithSignedReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCertificateWithSignedReport")
    @ResponseWrapper(localName = "VerifyCertificateWithSignedReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCertificateWithSignedReportResponse")
    public VerificationResultWithSignedReport verifyCertificateWithSignedReport(
        @WebParam(name = "certificate", targetNamespace = "http://esv.server.rt.ru")
        byte[] certificate);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResult
     */
    @WebMethod(operationName = "VerifyCMSSignature", action = "http://esv.server.rt.ru/VerifyCMSSignature")
    @WebResult(name = "VerifyCMSSignatureResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCMSSignature", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignature")
    @ResponseWrapper(localName = "VerifyCMSSignatureResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureResponse")
    public VerificationResult verifyCMSSignature(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithReport
     */
    @WebMethod(operationName = "VerifyCMSSignatureWithReport", action = "http://esv.server.rt.ru/VerifyCMSSignatureWithReport")
    @WebResult(name = "VerifyCMSSignatureWithReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCMSSignatureWithReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureWithReport")
    @ResponseWrapper(localName = "VerifyCMSSignatureWithReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureWithReportResponse")
    public VerificationResultWithReport verifyCMSSignatureWithReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithSignedReport
     */
    @WebMethod(operationName = "VerifyCMSSignatureWithSignedReport", action = "http://esv.server.rt.ru/VerifyCMSSignatureWithSignedReport")
    @WebResult(name = "VerifyCMSSignatureWithSignedReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCMSSignatureWithSignedReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureWithSignedReport")
    @ResponseWrapper(localName = "VerifyCMSSignatureWithSignedReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureWithSignedReportResponse")
    public VerificationResultWithSignedReport verifyCMSSignatureWithSignedReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @param originalContent
     * @return
     *     returns ru.rt.server.esv.VerificationResult
     */
    @WebMethod(operationName = "VerifyCMSSignatureDetached", action = "http://esv.server.rt.ru/VerifyCMSSignatureDetached")
    @WebResult(name = "VerifyCMSSignatureDetachedResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCMSSignatureDetached", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureDetached")
    @ResponseWrapper(localName = "VerifyCMSSignatureDetachedResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureDetachedResponse")
    public VerificationResult verifyCMSSignatureDetached(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "originalContent", targetNamespace = "http://esv.server.rt.ru")
        byte[] originalContent,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @param originalContent
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithReport
     */
    @WebMethod(operationName = "VerifyCMSSignatureDetachedWithReport", action = "http://esv.server.rt.ru/VerifyCMSSignatureDetachedWithReport")
    @WebResult(name = "VerifyCMSSignatureDetachedWithReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCMSSignatureDetachedWithReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureDetachedWithReport")
    @ResponseWrapper(localName = "VerifyCMSSignatureDetachedWithReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureDetachedWithReportResponse")
    public VerificationResultWithReport verifyCMSSignatureDetachedWithReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "originalContent", targetNamespace = "http://esv.server.rt.ru")
        byte[] originalContent,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @param originalContent
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithSignedReport
     */
    @WebMethod(operationName = "VerifyCMSSignatureDetachedWithSignedReport", action = "http://esv.server.rt.ru/VerifyCMSSignatureDetachedWithSignedReport")
    @WebResult(name = "VerifyCMSSignatureDetachedWithSignedReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCMSSignatureDetachedWithSignedReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureDetachedWithSignedReport")
    @ResponseWrapper(localName = "VerifyCMSSignatureDetachedWithSignedReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureDetachedWithSignedReportResponse")
    public VerificationResultWithSignedReport verifyCMSSignatureDetachedWithSignedReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "originalContent", targetNamespace = "http://esv.server.rt.ru")
        byte[] originalContent,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @param hash
     * @return
     *     returns ru.rt.server.esv.VerificationResult
     */
    @WebMethod(operationName = "VerifyCMSSignatureByHash", action = "http://esv.server.rt.ru/VerifyCMSSignatureByHash")
    @WebResult(name = "VerifyCMSSignatureByHashResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCMSSignatureByHash", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureByHash")
    @ResponseWrapper(localName = "VerifyCMSSignatureByHashResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureByHashResponse")
    public VerificationResult verifyCMSSignatureByHash(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "hash", targetNamespace = "http://esv.server.rt.ru")
        byte[] hash,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @param hash
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithReport
     */
    @WebMethod(operationName = "VerifyCMSSignatureByHashWithReport", action = "http://esv.server.rt.ru/VerifyCMSSignatureByHashWithReport")
    @WebResult(name = "VerifyCMSSignatureByHashWithReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCMSSignatureByHashWithReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureByHashWithReport")
    @ResponseWrapper(localName = "VerifyCMSSignatureByHashWithReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureByHashWithReportResponse")
    public VerificationResultWithReport verifyCMSSignatureByHashWithReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "hash", targetNamespace = "http://esv.server.rt.ru")
        byte[] hash,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @param hash
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithSignedReport
     */
    @WebMethod(operationName = "VerifyCMSSignatureByHashWithSignedReport", action = "http://esv.server.rt.ru/VerifyCMSSignatureByHashWithSignedReport")
    @WebResult(name = "VerifyCMSSignatureByHashWithSignedReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCMSSignatureByHashWithSignedReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureByHashWithSignedReport")
    @ResponseWrapper(localName = "VerifyCMSSignatureByHashWithSignedReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCMSSignatureByHashWithSignedReportResponse")
    public VerificationResultWithSignedReport verifyCMSSignatureByHashWithSignedReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "hash", targetNamespace = "http://esv.server.rt.ru")
        byte[] hash,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResult
     */
    @WebMethod(operationName = "VerifyXMLSignature", action = "http://esv.server.rt.ru/VerifyXMLSignature")
    @WebResult(name = "VerifyXMLSignatureResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyXMLSignature", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXMLSignature")
    @ResponseWrapper(localName = "VerifyXMLSignatureResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXMLSignatureResponse")
    public VerificationResult verifyXMLSignature(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithReport
     */
    @WebMethod(operationName = "VerifyXMLSignatureWithReport", action = "http://esv.server.rt.ru/VerifyXMLSignatureWithReport")
    @WebResult(name = "VerifyXMLSignatureWithReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyXMLSignatureWithReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXMLSignatureWithReport")
    @ResponseWrapper(localName = "VerifyXMLSignatureWithReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXMLSignatureWithReportResponse")
    public VerificationResultWithReport verifyXMLSignatureWithReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithSignedReport
     */
    @WebMethod(operationName = "VerifyXMLSignatureWithSignedReport", action = "http://esv.server.rt.ru/VerifyXMLSignatureWithSignedReport")
    @WebResult(name = "VerifyXMLSignatureWithSignedReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyXMLSignatureWithSignedReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXMLSignatureWithSignedReport")
    @ResponseWrapper(localName = "VerifyXMLSignatureWithSignedReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXMLSignatureWithSignedReportResponse")
    public VerificationResultWithSignedReport verifyXMLSignatureWithSignedReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResult
     */
    @WebMethod(operationName = "VerifyWSSSignature", action = "http://esv.server.rt.ru/VerifyWSSSignature")
    @WebResult(name = "VerifyWSSSignatureResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyWSSSignature", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyWSSSignature")
    @ResponseWrapper(localName = "VerifyWSSSignatureResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyWSSSignatureResponse")
    public VerificationResult verifyWSSSignature(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithReport
     */
    @WebMethod(operationName = "VerifyWSSSignatureWithReport", action = "http://esv.server.rt.ru/VerifyWSSSignatureWithReport")
    @WebResult(name = "VerifyWSSSignatureWithReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyWSSSignatureWithReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyWSSSignatureWithReport")
    @ResponseWrapper(localName = "VerifyWSSSignatureWithReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyWSSSignatureWithReportResponse")
    public VerificationResultWithReport verifyWSSSignatureWithReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithSignedReport
     */
    @WebMethod(operationName = "VerifyWSSSignatureWithSignedReport", action = "http://esv.server.rt.ru/VerifyWSSSignatureWithSignedReport")
    @WebResult(name = "VerifyWSSSignatureWithSignedReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyWSSSignatureWithSignedReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyWSSSignatureWithSignedReport")
    @ResponseWrapper(localName = "VerifyWSSSignatureWithSignedReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyWSSSignatureWithSignedReportResponse")
    public VerificationResultWithSignedReport verifyWSSSignatureWithSignedReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResult
     */
    @WebMethod(operationName = "VerifyAttachment", action = "http://esv.server.rt.ru/VerifyAttachment")
    @WebResult(name = "VerifyAttachmentResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyAttachment", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyAttachment")
    @ResponseWrapper(localName = "VerifyAttachmentResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyAttachmentResponse")
    public VerificationResult verifyAttachment(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithReport
     */
    @WebMethod(operationName = "VerifyAttachmentWithReport", action = "http://esv.server.rt.ru/VerifyAttachmentWithReport")
    @WebResult(name = "VerifyAttachmentWithReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyAttachmentWithReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyAttachmentWithReport")
    @ResponseWrapper(localName = "VerifyAttachmentWithReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyAttachmentWithReportResponse")
    public VerificationResultWithReport verifyAttachmentWithReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithSignedReport
     */
    @WebMethod(operationName = "VerifyAttachmentWithSignedReport", action = "http://esv.server.rt.ru/VerifyAttachmentWithSignedReport")
    @WebResult(name = "VerifyAttachmentWithSignedReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyAttachmentWithSignedReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyAttachmentWithSignedReport")
    @ResponseWrapper(localName = "VerifyAttachmentWithSignedReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyAttachmentWithSignedReportResponse")
    public VerificationResultWithSignedReport verifyAttachmentWithSignedReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResult
     */
    @WebMethod(operationName = "VerifyPAdES", action = "http://esv.server.rt.ru/VerifyPAdES")
    @WebResult(name = "VerifyPAdESResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyPAdES", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyPAdES")
    @ResponseWrapper(localName = "VerifyPAdESResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyPAdESResponse")
    public VerificationResult verifyPAdES(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithReport
     */
    @WebMethod(operationName = "VerifyPAdESWithReport", action = "http://esv.server.rt.ru/VerifyPAdESWithReport")
    @WebResult(name = "VerifyPAdESWithReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyPAdESWithReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyPAdESWithReport")
    @ResponseWrapper(localName = "VerifyPAdESWithReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyPAdESWithReportResponse")
    public VerificationResultWithReport verifyPAdESWithReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithSignedReport
     */
    @WebMethod(operationName = "VerifyPAdESWithSignedReport", action = "http://esv.server.rt.ru/VerifyPAdESWithSignedReport")
    @WebResult(name = "VerifyPAdESWithSignedReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyPAdESWithSignedReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyPAdESWithSignedReport")
    @ResponseWrapper(localName = "VerifyPAdESWithSignedReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyPAdESWithSignedReportResponse")
    public VerificationResultWithSignedReport verifyPAdESWithSignedReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     *
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResult
     */
    @WebMethod(operationName = "VerifyXAdES", action = "http://esv.server.rt.ru/VerifyXAdES")
    @WebResult(name = "VerifyXAdESResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyXAdES", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXAdES")
    @ResponseWrapper(localName = "VerifyXAdESResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXAdESResponse")
    public VerificationResult verifyXAdES(
            @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
            byte[] message,
            @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
            boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithReport
     */
    @WebMethod(operationName = "VerifyXAdESWithReport", action = "http://esv.server.rt.ru/VerifyXAdESWithReport")
    @WebResult(name = "VerifyXAdESWithReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyXAdESWithReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXAdESWithReport")
    @ResponseWrapper(localName = "VerifyXAdESWithReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXAdESWithReportResponse")
    public VerificationResultWithReport verifyXAdESWithReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithSignedReport
     */
    @WebMethod(operationName = "VerifyXAdESWithSignedReport", action = "http://esv.server.rt.ru/VerifyXAdESWithSignedReport")
    @WebResult(name = "VerifyXAdESWithSignedReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyXAdESWithSignedReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXAdESWithSignedReport")
    @ResponseWrapper(localName = "VerifyXAdESWithSignedReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyXAdESWithSignedReportResponse")
    public VerificationResultWithSignedReport verifyXAdESWithSignedReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResult
     */
    @WebMethod(operationName = "VerifyCAdES", action = "http://esv.server.rt.ru/VerifyCAdES")
    @WebResult(name = "VerifyCAdESResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCAdES", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCAdES")
    @ResponseWrapper(localName = "VerifyCAdESResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCAdESResponse")
    public VerificationResult verifyCAdES(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithReport
     */
    @WebMethod(operationName = "VerifyCAdESWithReport", action = "http://esv.server.rt.ru/VerifyCAdESWithReport")
    @WebResult(name = "VerifyCAdESWithReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCAdESWithReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCAdESWithReport")
    @ResponseWrapper(localName = "VerifyCAdESWithReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCAdESWithReportResponse")
    public VerificationResultWithReport verifyCAdESWithReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param message
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithSignedReport
     */
    @WebMethod(operationName = "VerifyCAdESWithSignedReport", action = "http://esv.server.rt.ru/VerifyCAdESWithSignedReport")
    @WebResult(name = "VerifyCAdESWithSignedReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyCAdESWithSignedReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCAdESWithSignedReport")
    @ResponseWrapper(localName = "VerifyCAdESWithSignedReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyCAdESWithSignedReportResponse")
    public VerificationResultWithSignedReport verifyCAdESWithSignedReport(
        @WebParam(name = "message", targetNamespace = "http://esv.server.rt.ru")
        byte[] message,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param stamp
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResult
     */
    @WebMethod(operationName = "VerifyTimeStamp", action = "http://esv.server.rt.ru/VerifyTimeStamp")
    @WebResult(name = "VerifyTimeStampResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyTimeStamp", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyTimeStamp")
    @ResponseWrapper(localName = "VerifyTimeStampResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyTimeStampResponse")
    public VerificationResult verifyTimeStamp(
        @WebParam(name = "stamp", targetNamespace = "http://esv.server.rt.ru")
        byte[] stamp,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param stamp
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithReport
     */
    @WebMethod(operationName = "VerifyTimeStampWithReport", action = "http://esv.server.rt.ru/VerifyTimeStampWithReport")
    @WebResult(name = "VerifyTimeStampWithReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyTimeStampWithReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyTimeStampWithReport")
    @ResponseWrapper(localName = "VerifyTimeStampWithReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyTimeStampWithReportResponse")
    public VerificationResultWithReport verifyTimeStampWithReport(
        @WebParam(name = "stamp", targetNamespace = "http://esv.server.rt.ru")
        byte[] stamp,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

    /**
     * 
     * @param stamp
     * @param verifySignatureOnly
     * @return
     *     returns ru.rt.server.esv.VerificationResultWithSignedReport
     */
    @WebMethod(operationName = "VerifyTimeStampWithSignedReport", action = "http://esv.server.rt.ru/VerifyTimeStampWithSignedReport")
    @WebResult(name = "VerifyTimeStampWithSignedReportResult", targetNamespace = "http://esv.server.rt.ru")
    @RequestWrapper(localName = "VerifyTimeStampWithSignedReport", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyTimeStampWithSignedReport")
    @ResponseWrapper(localName = "VerifyTimeStampWithSignedReportResponse", targetNamespace = "http://esv.server.rt.ru", className = "ru.rt.server.esv.VerifyTimeStampWithSignedReportResponse")
    public VerificationResultWithSignedReport verifyTimeStampWithSignedReport(
        @WebParam(name = "stamp", targetNamespace = "http://esv.server.rt.ru")
        byte[] stamp,
        @WebParam(name = "verifySignatureOnly", targetNamespace = "http://esv.server.rt.ru")
        boolean verifySignatureOnly);

}
