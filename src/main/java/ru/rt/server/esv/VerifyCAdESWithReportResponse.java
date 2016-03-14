
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
 *         &lt;element name="VerifyCAdESWithReportResult" type="{http://esv.server.rt.ru}VerificationResultWithReport" minOccurs="0"/>
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
    "verifyCAdESWithReportResult"
})
@XmlRootElement(name = "VerifyCAdESWithReportResponse")
public class VerifyCAdESWithReportResponse {

    @XmlElement(name = "VerifyCAdESWithReportResult")
    protected VerificationResultWithReport verifyCAdESWithReportResult;

    /**
     * Gets the value of the verifyCAdESWithReportResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResultWithReport }
     *     
     */
    public VerificationResultWithReport getVerifyCAdESWithReportResult() {
        return verifyCAdESWithReportResult;
    }

    /**
     * Sets the value of the verifyCAdESWithReportResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResultWithReport }
     *     
     */
    public void setVerifyCAdESWithReportResult(VerificationResultWithReport value) {
        this.verifyCAdESWithReportResult = value;
    }

}
