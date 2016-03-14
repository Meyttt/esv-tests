
package ru.rt.server.esv;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
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
 *         &lt;element name="stamp" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/>
 *         &lt;element name="verifySignatureOnly" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
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
    "stamp",
    "verifySignatureOnly"
})
@XmlRootElement(name = "VerifyTimeStamp")
public class VerifyTimeStamp {

    protected byte[] stamp;
    protected boolean verifySignatureOnly;

    /**
     * Gets the value of the stamp property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getStamp() {
        return stamp;
    }

    /**
     * Sets the value of the stamp property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setStamp(byte[] value) {
        this.stamp = value;
    }

    /**
     * Gets the value of the verifySignatureOnly property.
     * 
     */
    public boolean isVerifySignatureOnly() {
        return verifySignatureOnly;
    }

    /**
     * Sets the value of the verifySignatureOnly property.
     * 
     */
    public void setVerifySignatureOnly(boolean value) {
        this.verifySignatureOnly = value;
    }

}
