/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.processor;

import com.google.auto.service.AutoService;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.Trees;
import java.util.Set;
import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.ProcessingEnvironment;
import javax.annotation.processing.Processor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import org.zaproxy.annotation.ZapStatsKey;

/**
 * Enforces that any method invoking Stats.incCounter("…") is annotated with @StatsKey(name="…")
 * matching the literal string.
 */
@SupportedAnnotationTypes("*")
@SupportedSourceVersion(SourceVersion.RELEASE_17)
@AutoService(Processor.class)
public class ZapStatsKeyChecker extends AbstractProcessor {
    private Trees trees;

    @Override
    public synchronized void init(ProcessingEnvironment processingEnv) {
        super.init(processingEnv);
        trees = Trees.instance(processingEnv);
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {

        for (Element root : roundEnv.getRootElements()) {
            TreePath path = trees.getPath(root);
            if (path == null) continue;

            new TreePathScanner<Void, Void>() {
                @Override
                public Void visitMethod(MethodTree methodTree, Void unused) {
                    StatsData statsData = new StatsData();

                    // scan method body
                    new TreeScanner<Void, Void>() {
                        @Override
                        public Void visitMethodInvocation(MethodInvocationTree mit, Void v) {
                            ExpressionTree sel = mit.getMethodSelect();
                            String invoked = sel.toString();
                            if (invoked.endsWith("Stats.incCounter")
                                    && mit.getArguments().size() == 1) {
                                ExpressionTree arg = mit.getArguments().get(0);
                                if (arg instanceof LiteralTree lit
                                        && lit.getValue() instanceof String s) {
                                    statsData.setCallsStats(true);
                                    statsData.setExpectedKey(s);
                                }
                            }
                            return super.visitMethodInvocation(mit, v);
                        }
                    }.scan(methodTree.getBody(), null);

                    if (statsData.isCallsStats()) {
                        Element methodElt = trees.getElement(getCurrentPath());
                        ZapStatsKey ann = methodElt.getAnnotation(ZapStatsKey.class);
                        if (ann == null) {
                            processingEnv
                                    .getMessager()
                                    .printMessage(
                                            Diagnostic.Kind.ERROR,
                                            "Calls Stats.incCounter but missing @StatsKey", // TODO
                                            methodElt);
                        } else if (!statsData.getExpectedKey().equals(ann.name())) {
                            processingEnv
                                    .getMessager()
                                    .printMessage(
                                            Diagnostic.Kind.ERROR,
                                            "@StatsKey name=\""
                                                    + ann.name()
                                                    + "\" doesn't match Stats.incCounter key=\""
                                                    + statsData.getExpectedKey()
                                                    + "\"",
                                            methodElt);
                        }
                    }

                    return super.visitMethod(methodTree, unused);
                }
            }.scan(path, null);
        }

        return false;
    }

    private class StatsData {
        boolean callsStats = false;
        String expectedKey = null;

        public boolean isCallsStats() {
            return callsStats;
        }

        public void setCallsStats(boolean callsStats) {
            this.callsStats = callsStats;
        }

        public String getExpectedKey() {
            return expectedKey;
        }

        public void setExpectedKey(String expectedKey) {
            this.expectedKey = expectedKey;
        }
    }
}
