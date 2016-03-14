
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
 *         &lt;element name="VerifyWSSSignatureWithReportResult" type="{http://esv.server.rt.ru}VerificationResultWithReport" minOccurs="0"/>
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
    "verifyWSSSignatureWithReportResult"
})
@XmlRootElement(name = "VerifyWSSSignatureWithReportResponse")
public class VerifyWSSSignatureWithReportResponse {

    @XmlElement(name = "VerifyWSSSignatureWithReportResult")
    protected VerificationResultWithReport verifyWSSSignatureWithReportResult;

    /**
     * Gets the value of the verifyWSSSignatureWithReportResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResultWithReport }
     *     
     */
    public VerificationResultWithReport getVerifyWSSSignatureWithReportResult() {
        return verifyWSSSignatureWithReportResult;
    }

    /**
     * Sets the value of the verifyWSSSignatureWithReportResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResultWithReport }
     *     
     */
    public void setVerifyWSSSignatureWithReportResult(VerificationResultWithReport value) {
        this.verifyWSSSignatureWithReportResult = value;
    }

}
