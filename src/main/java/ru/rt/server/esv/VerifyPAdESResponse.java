
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
 *         &lt;element name="VerifyPAdESResult" type="{http://esv.server.rt.ru}VerificationResult" minOccurs="0"/>
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
    "verifyPAdESResult"
})
@XmlRootElement(name = "VerifyPAdESResponse")
public class VerifyPAdESResponse {

    @XmlElement(name = "VerifyPAdESResult")
    protected VerificationResult verifyPAdESResult;

    /**
     * Gets the value of the verifyPAdESResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResult }
     *     
     */
    public VerificationResult getVerifyPAdESResult() {
        return verifyPAdESResult;
    }

    /**
     * Sets the value of the verifyPAdESResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResult }
     *     
     */
    public void setVerifyPAdESResult(VerificationResult value) {
        this.verifyPAdESResult = value;
    }

}
