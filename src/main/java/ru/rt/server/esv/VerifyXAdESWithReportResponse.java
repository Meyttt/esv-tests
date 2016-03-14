
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
 *         &lt;element name="VerifyXAdESWithReportResult" type="{http://esv.server.rt.ru}VerificationResultWithReport" minOccurs="0"/>
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
    "verifyXAdESWithReportResult"
})
@XmlRootElement(name = "VerifyXAdESWithReportResponse")
public class VerifyXAdESWithReportResponse {

    @XmlElement(name = "VerifyXAdESWithReportResult")
    protected VerificationResultWithReport verifyXAdESWithReportResult;

    /**
     * Gets the value of the verifyXAdESWithReportResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResultWithReport }
     *     
     */
    public VerificationResultWithReport getVerifyXAdESWithReportResult() {
        return verifyXAdESWithReportResult;
    }

    /**
     * Sets the value of the verifyXAdESWithReportResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResultWithReport }
     *     
     */
    public void setVerifyXAdESWithReportResult(VerificationResultWithReport value) {
        this.verifyXAdESWithReportResult = value;
    }

}
