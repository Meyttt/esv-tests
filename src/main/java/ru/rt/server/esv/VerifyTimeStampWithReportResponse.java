
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
 *         &lt;element name="VerifyTimeStampWithReportResult" type="{http://esv.server.rt.ru}VerificationResultWithReport" minOccurs="0"/>
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
    "verifyTimeStampWithReportResult"
})
@XmlRootElement(name = "VerifyTimeStampWithReportResponse")
public class VerifyTimeStampWithReportResponse {

    @XmlElement(name = "VerifyTimeStampWithReportResult")
    protected VerificationResultWithReport verifyTimeStampWithReportResult;

    /**
     * Gets the value of the verifyTimeStampWithReportResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResultWithReport }
     *     
     */
    public VerificationResultWithReport getVerifyTimeStampWithReportResult() {
        return verifyTimeStampWithReportResult;
    }

    /**
     * Sets the value of the verifyTimeStampWithReportResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResultWithReport }
     *     
     */
    public void setVerifyTimeStampWithReportResult(VerificationResultWithReport value) {
        this.verifyTimeStampWithReportResult = value;
    }

}
