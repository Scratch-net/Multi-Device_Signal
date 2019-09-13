package org.whispersystems.libsignal.state.impl;

import com.google.protobuf.ByteString;

import org.whispersystems.libsignal.state.DeviceKeyStore;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

public class InMemoryDeviceKeyStore implements DeviceKeyStore {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private LinkedHashSet<PublicKey> allDevicesKeys = new LinkedHashSet<PublicKey>();


    public InMemoryDeviceKeyStore(KeyPair keyPair) {
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    public InMemoryDeviceKeyStore() {

    }

    public PublicKey getDevicePublicKey() {
        return publicKey;
    }

    public PrivateKey getDevicePrivateKey() {
        return privateKey;
    }


    public List<ByteString> getDevicesPublicKeys(){
        List<ByteString> keys = new ArrayList<ByteString>();
        for(PublicKey pk : allDevicesKeys){
                keys.add(ByteString.copyFrom(pk.getEncoded()));
        }
        return keys;
    }

    @Override
    public int getDeviceKeyIndex(PublicKey pk) {
        int i = 1; // own key must accounted
        for (PublicKey p: allDevicesKeys) {
            if (p.equals(pk)) {
                return i;
            } else {
                i++;
            }
        }
        return -1;
    }

    @Override
    public void delDevicePublicKey(PublicKey pk) {
        allDevicesKeys.remove(pk);
    }

    public void addDeviceKey(PublicKey pk){
        allDevicesKeys.add(pk);
    }
}