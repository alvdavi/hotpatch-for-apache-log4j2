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
import com.amazon.corretto.hotpatch.patch.ClassTransformerHotPatch;

/**
 * This will patch the CachedIntrospectionResults in spring-beans to fix a RCE disclosed as CVE-2022-22965, also known
 * as SpringShell or Spring4Shell.
 *
 * The patch limits access to the class property completely. This is an aggressive approach and is not the path chosen
 * by the Spring developers to fix this vulnerability
 *
 * @see <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-22965">CVE-2022-22965</a>
 * @see <a href="https://github.com/spring-projects/spring-framework/commit/002546b3e4b8d791ea6acccb81eb3168f51abb15">
 *     Spring fix</a>
 */
public class Spring_2022_22965_1 implements ClassTransformerHotPatch {
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

        private boolean classLoaderCompare = false;

        @Override
        public void visitCode() {
            logger.log("Entering CachedIntrospectionResults::<init>");
            mv.visitCode();
            mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
            mv.visitLdcInsn("-> Calling CachedIntrospectionResults::<init>");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        }

        @Override
        public void visitLdcInsn(Object value) {
            if (value instanceof String && "classLoader".equals(value)) {
                classLoaderCompare = true;
                logger.log("Found ldc classLoader");
            } else {
                classLoaderCompare = false;
            }
            mv.visitLdcInsn(value);
        }

        @Override
        public void visitJumpInsn(int opcode, Label label) {
            logger.log("Visiting JumpInsn " + opcode + " (classLoaderCompare==" + classLoaderCompare + ")");
            if (classLoaderCompare && opcode == IFNE) {
                logger.log("Changing IFNE to GOTO");
                mv.visitInsn(POP);
                mv.visitJumpInsn(GOTO, label);
            } else {
                mv.visitJumpInsn(opcode, label);
            }
            classLoaderCompare = false;
        }
    }
}