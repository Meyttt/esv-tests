
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
 *         &lt;element name="VerifyPAdESWithSignedReportResult" type="{http://esv.server.rt.ru}VerificationResultWithSignedReport" minOccurs="0"/>
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
    "verifyPAdESWithSignedReportResult"
})
@XmlRootElement(name = "VerifyPAdESWithSignedReportResponse")
public class VerifyPAdESWithSignedReportResponse {

    @XmlElement(name = "VerifyPAdESWithSignedReportResult")
    protected VerificationResultWithSignedReport verifyPAdESWithSignedReportResult;

    /**
     * Gets the value of the verifyPAdESWithSignedReportResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResultWithSignedReport }
     *     
     */
    public VerificationResultWithSignedReport getVerifyPAdESWithSignedReportResult() {
        return verifyPAdESWithSignedReportResult;
    }

    /**
     * Sets the value of the verifyPAdESWithSignedReportResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResultWithSignedReport }
     *     
     */
    public void setVerifyPAdESWithSignedReportResult(VerificationResultWithSignedReport value) {
        this.verifyPAdESWithSignedReportResult = value;
    }

}
