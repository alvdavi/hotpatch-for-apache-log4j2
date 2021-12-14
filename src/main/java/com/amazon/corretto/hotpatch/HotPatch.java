package com.amazon.corretto.hotpatch;

public interface HotPatch {
    String getName();
    boolean isValidClass(String className);
    byte[] apply(byte[] classfileBuffer);

}
