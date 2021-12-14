package com.amazon.corretto.hotpatch;/*
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

import com.amazon.corretto.hotpatch.log4j.Log4jNoJndiLookup;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.security.ProtectionDomain;
import java.util.*;

import static com.amazon.corretto.hotpatch.Util.asmVersion;
import static com.amazon.corretto.hotpatch.Util.log;

//@SuppressWarnings({"JavaReflectionMemberAccess", "PointlessBitwiseExpression", "CatchMayIgnoreException"})
public class Log4jHotPatchAgent {
  private static boolean agentLoaded = false;
  private static boolean staticAgent = false; // Set to true if loaded as a static agent from 'premain()'

  private static List<HotPatch> loadPatches(String args) {
    List<HotPatch> patches = new ArrayList<>();
    if (Log4jNoJndiLookup.isEnabled(args)) {
      patches.add(new Log4jNoJndiLookup());
    }
    patches.forEach(it -> log("Loading patch " + it.getName()));
    return patches;
  }

  public static void agentmain(String args, Instrumentation inst) {
    if (agentLoaded) {
      log("Info: hot patch agent already loaded");
      return;
    }
    int asm = asmVersion();
    log("Loading Java Agent version " + Constants.log4jFixerAgentVersion + " (using ASM" + (asm >> 16) + ").");

    List<HotPatch> patches = loadPatches(args);
      ClassFileTransformer transformer = new ClassFileTransformer() {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
          if (className != null) {
            for (HotPatch patch : patches) {
              if (patch.isValidClass(className)) {
                log("Transforming + " + className + " (" + loader + ") with patch " + patch.getName());
                return patch.apply(classfileBuffer);
              }
            }
          }
          return null;
        }
      };


    if (!staticAgent) {
      int patchesApplied = 0;
      inst.addTransformer(transformer, true);
      List<Class<?>> classesToRetransform = new ArrayList<>();
      for (Class<?> c : inst.getAllLoadedClasses()) {
        String className = c.getName();
        for (HotPatch patch : patches) {
          if (patch.isValidClass(className)) {
            log("Patching + " + className + " (" + c.getClassLoader() + ") with patch " + patch.getName());
            classesToRetransform.add(c);
            ++patchesApplied;

          }
        }
      }
      if (classesToRetransform.size() > 0) {
        try {
          inst.retransformClasses(classesToRetransform.toArray(new Class[0]));
        } catch (UnmodifiableClassException uce) {
          log(String.valueOf(uce));
        }
      }

      if (patchesApplied == 0) {
        log("Vulnerable classes were not found. This agent will continue to run " +
            "and transform the vulnerable class if it is loaded. Note that if you have shaded " +
            "or otherwise changed the package name for log4j classes, then this tool may not " +
            "find them.");
      }
      inst.removeTransformer(transformer);
    }

    // Re-add the transformer with 'canRetransform' set to false
    // for class instances which might get loaded in the future.
    inst.addTransformer(transformer, false);
    agentLoaded = true;
    // set the version of this agent in a system property so that
    // subsequent clients can read it and skip re-patching.
    try {
      System.setProperty(Constants.LOG4J_FIXER_AGENT_VERSION, String.valueOf(Constants.log4jFixerAgentVersion));
    } catch (Exception e) {
      log("Warning: Could not record agent version in system property: " + e.getMessage());
      log("Warning: This will make it more difficult to test if agent is already loaded, but will not prevent patching");
    }
  }

  public static void premain(String args, Instrumentation inst) {
    staticAgent = true;
    agentmain(args, inst);
  }
}
