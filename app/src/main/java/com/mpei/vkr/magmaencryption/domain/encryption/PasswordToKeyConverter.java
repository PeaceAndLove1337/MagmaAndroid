package com.mpei.vkr.magmaencryption.domain.encryption;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordToKeyConverter {

    private final String mStringPassword;
    private Charset mCharset = StandardCharsets.UTF_8;

    public PasswordToKeyConverter(String stringPassword){
        mStringPassword = stringPassword;
    }

    public PasswordToKeyConverter(String stringPassword, Charset charset){
        mStringPassword = stringPassword;
        mCharset = charset;
    }

    public byte[] getBytesFromPassBySha(){
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return digest != null ? digest.digest(
                mStringPassword.getBytes(mCharset)) : new byte[0];
    }

    //todo
    public void getBytesFromPassByStreebog(){

    }


    private void sh(){
        System.out.println(mStringPassword);
    }
}
