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

package com.amazon.corretto.hotpatch.patch.impl.set;

import java.util.Collections;
import java.util.List;

import com.amazon.corretto.hotpatch.patch.ClassTransformerHotPatch;
import com.amazon.corretto.hotpatch.patch.impl.spring.Spring_2022_22965_1;
import com.amazon.corretto.hotpatch.patch.impl.spring.Spring_2022_22965_2;

public class SpringPatcher {
    /**
     * Empty patch set for Log4j2, that clears all previous patches from the JVM.
     */
    public static class SpringPatchSetV0 extends PatchSetPatcher {
        private final List<ClassTransformerHotPatch> patches = Collections.emptyList();

        @Override
        public List<ClassTransformerHotPatch> getPatches() {
            return patches;
        }

        @Override
        public String getName() {
            return "spring";
        }

        @Override
        public int getVersion() {
            return 0;
        }

        @Override
        public String getShortDescription() {
            return "Apply no patches related to spring";
        }
    }

    /**
     * Patch set that represent the initial patch approach for Spring4Shell, {@link Spring_2022_22965_1}.
     */
    public static class SpringPatchSetV1 extends PatchSetPatcher {
        private final List<ClassTransformerHotPatch> patches = Collections.singletonList(
                (ClassTransformerHotPatch) new Spring_2022_22965_1());

        @Override
        public List<ClassTransformerHotPatch> getPatches() {
            return patches;
        }

        @Override
        public String getName() {
            return "spring";
        }

        @Override
        public int getVersion() {
            return 1;
        }

        @Override
        public String getShortDescription() {
            return "Fix CVE-2022_22965 (Spring4Shell) in Spring blocking all class access";
        }
    }

    /**
     * Patch set that represent the initial patch approach for Spring4Shell, {@link Spring_2022_22965_1}.
     */
    public static class SpringPatchSetV2 extends PatchSetPatcher {
        private final List<ClassTransformerHotPatch> patches = Collections.singletonList(
                (ClassTransformerHotPatch) new Spring_2022_22965_2());

        @Override
        public List<ClassTransformerHotPatch> getPatches() {
            return patches;
        }

        @Override
        public String getName() {
            return "spring";
        }

        @Override
        public int getVersion() {
            return 2;
        }

        @Override
        public String getShortDescription() {
            return "Fix CVE-2022_22965 (Spring4Shell) in Spring blocking all class access except class.name";
        }
    }
}
