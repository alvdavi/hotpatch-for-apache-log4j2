/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.corretto.hotpatch.patch.impl.spring;

import com.amazon.corretto.hotpatch.interfaces.Logger;
import com.amazon.corretto.hotpatch.org.objectweb.asm.ClassReader;
import com.amazon.corretto.hotpatch.org.objectweb.asm.ClassVisitor;
import com.amazon.corretto.hotpatch.org.objectweb.asm.ClassWriter;
import com.amazon.corretto.hotpatch.org.objectweb.asm.Label;
import com.amazon.corretto.hotpatch.org.objectweb.asm.MethodVisitor;
import com.amazon.corretto.hotpatch.org.objectweb.asm.Opcodes;
import com.amazon.corretto.hotpatch.org.objectweb.asm.Type;
import com.amazon.corretto.hotpatch.patch.ClassTransformerHotPatch;

/**
 * This will patch the CachedIntrospectionResults in spring-beans to fix a RCE disclosed as CVE-2022-22965, also known
 * as SpringShell or Spring4Shell. It implements the same patch as the one it was released on spring 5.3.18 by limiting
 * properties of class that can be accessed to just name (the getName() method) and also limits any jump from a class
 * to a classLoader or a protectionDomain.
 *
 * @see <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-22965">CVE-2022-22965</a>
 * @see <a href="https://github.com/spring-projects/spring-framework/commit/002546b3e4b8d791ea6acccb81eb3168f51abb15">
 *     Spring fix</a>
 */
public class Spring_2022_22965_2 implements ClassTransformerHotPatch {
    static final String CLASS_NAME = "org.springframework.beans.CachedIntrospectionResults";
    static final String CLASS_NAME_SLASH = CLASS_NAME.replace(".", "/");

    private final static String NAME = "Spring_2022-22965";

    private Logger logger;

    @Override
    public String getName() {
        return NAME;
    }
    public String getDescription() {
        return "Fixes CVE-2022-22965by mirroring the patch released by Spring on 5.3.18";
    }

    @Override
    public boolean isTargetClass(String className) {
        return className.endsWith(CLASS_NAME)
                || className.endsWith(CLASS_NAME_SLASH);
    }

    @Override
    public byte[] apply(int asmApiVersion, String className, byte[] classfileBuffer, Logger logger) {
        this.logger = logger;
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new SpringClassVisitor(asmApiVersion, cw, logger);
        ClassReader cr = new ClassReader(classfileBuffer);
        cr.accept(cv, 0);
        return cw.toByteArray();
    }

    static class SpringClassVisitor extends ClassVisitor {
        private final Logger logger;

        public SpringClassVisitor(int asmApiVersion, ClassVisitor cv, Logger logger) {
            super(asmApiVersion, cv);
            this.logger = logger;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
            MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);
            if ("<init>".equals(name)) {
                logger.log("Found CachedIntrospectionResults::<init>");
                mv = new SpringMethodVisitor(api, mv, logger);
            }
            return mv;
        }
    }

    static class SpringMethodVisitor extends MethodVisitor implements Opcodes {
        private final Logger logger;

        public SpringMethodVisitor(int asmApiVersion, MethodVisitor mv, Logger log) {
            super(asmApiVersion, mv);
            this.logger = log;
        }

        private boolean patched = false;
        private boolean classCompare = false;
        private Label continueLabel = null;
        private int lastAstoreVar = -1;

        @Override
        public void visitLdcInsn(Object value) {
            if (Type.getObjectType("java/lang/Class").equals(value) && !classCompare && !patched) {
                // We have located the start of the critical part of the code
                classCompare = true;
                logger.log("Found 'ldc class java/lang/class'");
            }
            mv.visitLdcInsn(value);
        }

        @Override
        public void visitJumpInsn(int opcode, Label label) {
            if (classCompare && opcode == GOTO) {
                if (continueLabel == null) {
                    // We found our continueLabel
                    logger.log("Found the GOTO for the continue:" + label.toString());
                    this.continueLabel = label;
                }
            }
            mv.visitJumpInsn(opcode, label);
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
           if (classCompare && !patched && opcode == GETSTATIC && "logger".equals(name)) {
               logger.log("found entrypoint");
               // We have found the end of the critical part. Time to add our patch
               injectPatch();

               // And we are done
               patched = true;
               classCompare = false;
           }
           // visit the original FieldInsn
           mv.visitFieldInsn(opcode, owner, name, descriptor);
        }

        @Override
        public void visitVarInsn(int opcCode, int var) {
            if (!patched && !classCompare && opcCode == ASTORE) {
                logger.log("Last astore is:" + var);
                lastAstoreVar = var;
            }
            mv.visitVarInsn(opcCode, var);
        }

        private void injectPatch() {
            logger.log("patching. astore=" + lastAstoreVar);

            //This is the equivalent java code we are injecting, two different if checks
            //
            // if (Class.class == beanClass && (!"name".equals(pd.getName()) && !pd.getName().endsWith("Name"))) {
            //   continue;
            // }
            // secondIfLabel:
            // if (pd.getPropertyType() != null && (ClassLoader.class.isAssignableFrom(pd.getPropertyType())
            //         || ProtectionDomain.class.isAssignableFrom(pd.getPropertyType()))) {
            //   continue;
            // }
            // afterSecondIfLabel:

            // This code will make use of three labels
            // This label represents the beginning of the second if
            Label secondIfLabel = new Label();

            // This label represents the end of our injected code, execution of the loop iteration should continue
            Label afterSecondIfLabel = new Label();

            // Additionally, there is a continueLabel, that points to the end of the loop iteration
            // We do not insert this label, we read it from the code before


            mv.visitLdcInsn(Type.getObjectType("java/lang/Class"));
            mv.visitVarInsn(ALOAD, 1);
            mv.visitJumpInsn(IF_ACMPNE, secondIfLabel); // This goes to 193 (secondIfLabel)
            mv.visitLdcInsn("name");
            mv.visitVarInsn(ALOAD, lastAstoreVar);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/beans/PropertyDescriptor", "getName", "()Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
            mv.visitJumpInsn(IFNE, secondIfLabel); // This goes to 193 (secondIfLabel)
            mv.visitVarInsn(ALOAD, lastAstoreVar);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/beans/PropertyDescriptor", "getName", "()Ljava/lang/String;", false);
            mv.visitLdcInsn("Name");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "endsWith", "(Ljava/lang/String;)Z", false);
            mv.visitJumpInsn(IFNE, secondIfLabel);  // This goes to 193 (secondIfLabel)
            mv.visitJumpInsn(GOTO, continueLabel);  // This goes to 421 (continueLabel)
            mv.visitLabel(secondIfLabel); // The secondIfLabel. This is 193 for Spring 5.3.18
            mv.visitVarInsn(ALOAD, lastAstoreVar);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/beans/PropertyDescriptor", "getPropertyType", "()Ljava/lang/Class;", false);
            mv.visitJumpInsn(IFNULL, afterSecondIfLabel);  // This jumps to 230 (afterSecondIfLabel
            mv.visitLdcInsn(Type.getObjectType("java/lang/ClassLoader"));
            mv.visitVarInsn(ALOAD, lastAstoreVar);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/beans/PropertyDescriptor", "getPropertyType", "()Ljava/lang/Class;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "isAssignableFrom", "(Ljava/lang/Class;)Z", false);
            mv.visitJumpInsn(IFNE, continueLabel);  // this jumps to 421 (continueLabel)
            mv.visitLdcInsn(Type.getObjectType("java/security/ProtectionDomain"));
            mv.visitVarInsn(ALOAD, lastAstoreVar);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/beans/PropertyDescriptor", "getPropertyType", "()Ljava/lang/Class;", false);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "isAssignableFrom", "(Ljava/lang/Class;)Z", false);
            mv.visitJumpInsn(IFEQ,  afterSecondIfLabel); // This jumps to 230 (afterSecondIfLabel)
            mv.visitJumpInsn(GOTO, continueLabel); // This jumps to 421 (continueLabel)
            mv.visitLabel(afterSecondIfLabel); // The afterSecondIfLabel. This is 230 for Spring 5.3.18.
        }
    }
}