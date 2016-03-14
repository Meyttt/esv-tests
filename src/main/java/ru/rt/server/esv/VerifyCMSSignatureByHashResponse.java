
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
 *         &lt;element name="VerifyCMSSignatureByHashResult" type="{http://esv.server.rt.ru}VerificationResult" minOccurs="0"/>
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
    "verifyCMSSignatureByHashResult"
})
@XmlRootElement(name = "VerifyCMSSignatureByHashResponse")
public class VerifyCMSSignatureByHashResponse {

    @XmlElement(name = "VerifyCMSSignatureByHashResult")
    protected VerificationResult verifyCMSSignatureByHashResult;

    /**
     * Gets the value of the verifyCMSSignatureByHashResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResult }
     *     
     */
    public VerificationResult getVerifyCMSSignatureByHashResult() {
        return verifyCMSSignatureByHashResult;
    }

    /**
     * Sets the value of the verifyCMSSignatureByHashResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResult }
     *     
     */
    public void setVerifyCMSSignatureByHashResult(VerificationResult value) {
        this.verifyCMSSignatureByHashResult = value;
    }

}
