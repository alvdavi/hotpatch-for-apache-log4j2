package com.amazon.corretto.hotpatch;

import org.objectweb.asm.Opcodes;

public final class Util {
    // property name for verbose flag
    public static final String LOG4J_FIXER_VERBOSE = "log4jFixerVerbose";
    private static boolean verbose = Boolean.parseBoolean(System.getProperty(LOG4J_FIXER_VERBOSE, "true"));

    public static int asmVersion() {
        try {
            Opcodes.class.getDeclaredField("ASM8");
            return 8 << 16; // Opcodes.ASM8
        } catch (NoSuchFieldException nsfe) {}
        try {
            Opcodes.class.getDeclaredField("ASM7");
            return 7 << 16; // Opcodes.ASM7
        } catch (NoSuchFieldException nsfe) {}
        try {
            Opcodes.class.getDeclaredField("ASM6");
            return 6 << 16; // Opcodes.ASM6
        } catch (NoSuchFieldException nsfe) {}
        try {
            Opcodes.class.getDeclaredField("ASM5");
            return 5 << 16; // Opcodes.ASM5
        } catch (NoSuchFieldException nsfe) {}
        log("Warning: ASM5 doesn't seem to be supported");
        return Opcodes.ASM4;
    }

    public static void log(final String message) {
        if (verbose) {
            System.out.println(message);
        }
    }

    public static void log(final Exception ex) {
        if (verbose) {
            ex.printStackTrace(System.out);
        }
    }

    public static void setVerbose(String args) {
        verbose = args == null || args.contains("--verbose") || args.contains("--log4jFixerVerbose=true");
    }

    public static boolean isVerbose() {
        return verbose;
    }

    public static String getVerboseString() {
        return "--log4jFixerVerbose=" + Util.isVerbose();
    }
}
