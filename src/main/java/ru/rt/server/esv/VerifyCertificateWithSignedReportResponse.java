
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
 *         &lt;element name="VerifyCertificateWithSignedReportResult" type="{http://esv.server.rt.ru}VerificationResultWithSignedReport" minOccurs="0"/>
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
    "verifyCertificateWithSignedReportResult"
})
@XmlRootElement(name = "VerifyCertificateWithSignedReportResponse")
public class VerifyCertificateWithSignedReportResponse {

    @XmlElement(name = "VerifyCertificateWithSignedReportResult")
    protected VerificationResultWithSignedReport verifyCertificateWithSignedReportResult;

    /**
     * Gets the value of the verifyCertificateWithSignedReportResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResultWithSignedReport }
     *     
     */
    public VerificationResultWithSignedReport getVerifyCertificateWithSignedReportResult() {
        return verifyCertificateWithSignedReportResult;
    }

    /**
     * Sets the value of the verifyCertificateWithSignedReportResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResultWithSignedReport }
     *     
     */
    public void setVerifyCertificateWithSignedReportResult(VerificationResultWithSignedReport value) {
        this.verifyCertificateWithSignedReportResult = value;
    }

}
