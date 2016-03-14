
package ru.rt.server.esv;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="VerifyXMLSignatureWithSignedReportResult" type="{http://esv.server.rt.ru}VerificationResultWithSignedReport" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "verifyXMLSignatureWithSignedReportResult"
})
@XmlRootElement(name = "VerifyXMLSignatureWithSignedReportResponse")
public class VerifyXMLSignatureWithSignedReportResponse {

    @XmlElement(name = "VerifyXMLSignatureWithSignedReportResult")
    protected VerificationResultWithSignedReport verifyXMLSignatureWithSignedReportResult;

    /**
     * Gets the value of the verifyXMLSignatureWithSignedReportResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResultWithSignedReport }
     *     
     */
    public VerificationResultWithSignedReport getVerifyXMLSignatureWithSignedReportResult() {
        return verifyXMLSignatureWithSignedReportResult;
    }

    /**
     * Sets the value of the verifyXMLSignatureWithSignedReportResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResultWithSignedReport }
     *     
     */
    public void setVerifyXMLSignatureWithSignedReportResult(VerificationResultWithSignedReport value) {
        this.verifyXMLSignatureWithSignedReportResult = value;
    }

}
