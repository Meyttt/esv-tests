
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
 *         &lt;element name="VerifyWSSSignatureResult" type="{http://esv.server.rt.ru}VerificationResult" minOccurs="0"/>
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
    "verifyWSSSignatureResult"
})
@XmlRootElement(name = "VerifyWSSSignatureResponse")
public class VerifyWSSSignatureResponse {

    @XmlElement(name = "VerifyWSSSignatureResult")
    protected VerificationResult verifyWSSSignatureResult;

    /**
     * Gets the value of the verifyWSSSignatureResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResult }
     *     
     */
    public VerificationResult getVerifyWSSSignatureResult() {
        return verifyWSSSignatureResult;
    }

    /**
     * Sets the value of the verifyWSSSignatureResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResult }
     *     
     */
    public void setVerifyWSSSignatureResult(VerificationResult value) {
        this.verifyWSSSignatureResult = value;
    }

}
