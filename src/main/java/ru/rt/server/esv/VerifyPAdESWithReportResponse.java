
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
 *         &lt;element name="VerifyPAdESWithReportResult" type="{http://esv.server.rt.ru}VerificationResultWithReport" minOccurs="0"/>
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
    "verifyPAdESWithReportResult"
})
@XmlRootElement(name = "VerifyPAdESWithReportResponse")
public class VerifyPAdESWithReportResponse {

    @XmlElement(name = "VerifyPAdESWithReportResult")
    protected VerificationResultWithReport verifyPAdESWithReportResult;

    /**
     * Gets the value of the verifyPAdESWithReportResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResultWithReport }
     *     
     */
    public VerificationResultWithReport getVerifyPAdESWithReportResult() {
        return verifyPAdESWithReportResult;
    }

    /**
     * Sets the value of the verifyPAdESWithReportResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResultWithReport }
     *     
     */
    public void setVerifyPAdESWithReportResult(VerificationResultWithReport value) {
        this.verifyPAdESWithReportResult = value;
    }

}
