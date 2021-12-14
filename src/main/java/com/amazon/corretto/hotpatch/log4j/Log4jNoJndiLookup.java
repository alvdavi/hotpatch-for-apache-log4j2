package com.amazon.corretto.hotpatch.log4j;

import com.amazon.corretto.hotpatch.HotPatch;
import org.objectweb.asm.*;

import static com.amazon.corretto.hotpatch.Util.asmVersion;
import static com.amazon.corretto.hotpatch.Util.log;

public class Log4jNoJndiLookup implements HotPatch {
    static final String CLASS_NAME = "org.apache.logging.log4j.core.lookup.JndiLookup";
    static final String CLASS_NAME_SLASH = CLASS_NAME.replace(".", "/");

    private final static String NAME = "Log4jNoJndiLookup";

    @Override
    public String getName() {
        return NAME;
    }

    public static boolean isEnabled(String args) {
        String param = "--disable-" + NAME;
        return args == null || !args.contains(param);
    }

    @Override
    public boolean isValidClass(String className) {
        return className.endsWith(CLASS_NAME)
                || className.endsWith(CLASS_NAME_SLASH);
    }

    @Override
    public byte[] apply(byte[] classfileBuffer) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new NoJndiLookupClassVisitor(cw);
        ClassReader cr = new ClassReader(classfileBuffer);
        cr.accept(cv, 0);
        return cw.toByteArray();
    }

    public static class NoJndiLookupClassVisitor extends ClassVisitor {
        public NoJndiLookupClassVisitor(ClassVisitor cv) {
            super(asmVersion(), cv);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
            MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);
            if ("lookup".equals(name)) {
                mv = new NoJndiLookupMethodVisitor(mv);
            }
            return mv;
        }
    }

    public static class NoJndiLookupMethodVisitor extends MethodVisitor implements Opcodes {

        public NoJndiLookupMethodVisitor(MethodVisitor mv) {
            super(asmVersion(), mv);
        }

        @Override
        public void visitCode() {
            mv.visitCode();
            mv.visitLdcInsn("Patched JndiLookup::lookup()");
            mv.visitInsn(ARETURN);
        }
    }
}
