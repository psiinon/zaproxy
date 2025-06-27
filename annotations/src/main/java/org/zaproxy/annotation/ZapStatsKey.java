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
package org.zaproxy.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Indicates that the method updates the specified ZAP statistics key. Will be used to update
 * https://www.zaproxy.org/docs/internal-statistics/
 *
 * @see Stats
 * @see Statistics
 */

/*
 * WIP Notes
 * TODO
 * 	|	Get agreement for approach
 * 	|	Try out method annotation
 * 	|	Extract required data via ClassGraph
 * 	x	Can annotations replace code? No?
 * 		Generate data in format required for website
 * 		Add more annotations
 * 		Sort before printing out
 * 		Handle dups (we do have them)
 * 		Find methods without the annotation
 *
 */

// @Retention(RetentionPolicy.RUNTIME)
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.METHOD)
public @interface ZapStatsKey {

    enum Scope {
        GLOBAL,
        SITE;

        @Override
        public String toString() {
            return this.name();
        }
    }

    enum Type {
        COUNTER,
        HIGHWATERMARK
    }

    String name();

    Scope scope() default Scope.GLOBAL;

    Type type() default Type.COUNTER;

    String description();

    String version() default "";
}
