/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state.impl;

import com.google.protobuf.ByteString;

import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.StorageProtos;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class InMemoryPreKeyStore implements PreKeyStore {

  private final Map<Integer, byte[]> store = new HashMap<>();

  @Override
  public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
    try {
      if (!store.containsKey(preKeyId)) {
        throw new InvalidKeyIdException("No such prekeyrecord!");
      }

      return new PreKeyRecord(store.get(preKeyId));
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public void storePreKey(int preKeyId, PreKeyRecord record) {
    store.put(preKeyId, record.serialize());
  }

  @Override
  public boolean containsPreKey(int preKeyId) {
    return store.containsKey(preKeyId);
  }

  @Override
  public void removePreKey(int preKeyId) {
    store.remove(preKeyId);
  }

  @Override
  public void resetPreKey() {
    for (Integer i : store.keySet()) {
      ECKeyPair kp = Curve.generateKeyPair();
      PreKeyRecord preKeyRecord = new PreKeyRecord(i, kp);
      store.put(i, preKeyRecord.serialize());
    }
  }

  @Override
  public List<StorageProtos.PreKeyRecordStructure> dumpPreKey() {
    List<StorageProtos.PreKeyRecordStructure> allRecords = new ArrayList<StorageProtos.PreKeyRecordStructure>();
    for (Map.Entry<Integer, byte[]> sp : store.entrySet()) {
      try {
        SignedPreKeyRecord pkr = new SignedPreKeyRecord(sp.getValue());
        StorageProtos.PreKeyRecordStructure.Builder builder = StorageProtos.PreKeyRecordStructure.newBuilder()
                .setId(sp.getKey())
                .setPrivateKey(ByteString.copyFrom(pkr.getKeyPair().getPrivateKey().serialize()))
                .setPublicKey(ByteString.copyFrom(pkr.getKeyPair().getPublicKey().serialize()));
        allRecords.add(builder.build());
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
    return allRecords;
  }
}

