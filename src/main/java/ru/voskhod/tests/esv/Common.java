package ru.voskhod.tests.esv;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

public class Common {

    public static byte[] readFromFile(String filename) throws IOException {
        return FileUtils.readFileToByteArray(new File(filename));
    }

    //gp
    /*public static byte[] writeByteArrayToFile(String byte[]) throws IOException {
        return FileUtils.writeByteArrayToFile(new File(filename));
    }*/
    //gp
}
