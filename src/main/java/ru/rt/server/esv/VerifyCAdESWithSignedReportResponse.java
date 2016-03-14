
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
 *         &lt;element name="VerifyCAdESWithSignedReportResult" type="{http://esv.server.rt.ru}VerificationResultWithSignedReport" minOccurs="0"/>
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
    "verifyCAdESWithSignedReportResult"
})
@XmlRootElement(name = "VerifyCAdESWithSignedReportResponse")
public class VerifyCAdESWithSignedReportResponse {

    @XmlElement(name = "VerifyCAdESWithSignedReportResult")
    protected VerificationResultWithSignedReport verifyCAdESWithSignedReportResult;

    /**
     * Gets the value of the verifyCAdESWithSignedReportResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResultWithSignedReport }
     *     
     */
    public VerificationResultWithSignedReport getVerifyCAdESWithSignedReportResult() {
        return verifyCAdESWithSignedReportResult;
    }

    /**
     * Sets the value of the verifyCAdESWithSignedReportResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResultWithSignedReport }
     *     
     */
    public void setVerifyCAdESWithSignedReportResult(VerificationResultWithSignedReport value) {
        this.verifyCAdESWithSignedReportResult = value;
    }

}
