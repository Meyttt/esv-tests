
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
 *         &lt;element name="VerifyCAdESResult" type="{http://esv.server.rt.ru}VerificationResult" minOccurs="0"/>
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
    "verifyCAdESResult"
})
@XmlRootElement(name = "VerifyCAdESResponse")
public class VerifyCAdESResponse {

    @XmlElement(name = "VerifyCAdESResult")
    protected VerificationResult verifyCAdESResult;

    /**
     * Gets the value of the verifyCAdESResult property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationResult }
     *     
     */
    public VerificationResult getVerifyCAdESResult() {
        return verifyCAdESResult;
    }

    /**
     * Sets the value of the verifyCAdESResult property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationResult }
     *     
     */
    public void setVerifyCAdESResult(VerificationResult value) {
        this.verifyCAdESResult = value;
    }

}
