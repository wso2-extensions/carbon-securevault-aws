/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.securevault.aws.common;

import org.wso2.carbon.utils.CarbonUtils;

/**
 * Resolves the Carbon config directory path across different runtime environments.
 */
public class CarbonConfigResolver {

    /**
     * System property that explicitly overrides the Carbon config directory for this extension.
     */
    private static final String CONFIG_DIR_PROPERTY = "carbon.config.dir";

    /**
     * Standard Carbon system property carrying the config directory. This is the property that
     * CarbonUtils itself reads, and it is set by Carbon based products including Micro Integrator.
     */
    private static final String CONFIG_DIR_PATH_PROPERTY = "carbon.config.dir.path";

    private CarbonConfigResolver() {

    }

    /**
     * Returns the Carbon config directory path. Uses CarbonUtils.getCarbonConfigDirPath() when the
     * carbon.utils bundle is available (optional OSGi dependency). Falls back to the "carbon.config.dir"
     * and then the "carbon.config.dir.path" system properties for environments like Micro Integrator
     * that run without Carbon Kernel.
     *
     * @return the Carbon config directory path.
     * @throws IllegalStateException if neither CarbonUtils nor the system properties are available.
     */
    public static String getCarbonConfigDirPath() {

        try {
            return CarbonUtils.getCarbonConfigDirPath();
        } catch (NoClassDefFoundError e) {
            String configDir = getSystemProperty(CONFIG_DIR_PROPERTY);
            if (configDir == null) {
                configDir = getSystemProperty(CONFIG_DIR_PATH_PROPERTY);
            }
            if (configDir != null) {
                return configDir;
            }
            throw new IllegalStateException(
                    "Cannot resolve Carbon config directory: carbon.utils bundle is not available " +
                    "and neither the '" + CONFIG_DIR_PROPERTY + "' nor the '" + CONFIG_DIR_PATH_PROPERTY +
                    "' system property is set.", e);
        }
    }

    /**
     * Reads a system property and returns its trimmed value, or null if it is not set or is blank.
     * The value is used to build a filesystem path, so a blank value is rejected here to avoid
     * resolving to an unintended relative path.
     *
     * @param name name of the system property.
     * @return the trimmed property value, or null if it is not set or blank.
     */
    private static String getSystemProperty(String name) {

        String value = System.getProperty(name);
        if (value != null) {
            value = value.trim();
            if (!value.isEmpty()) {
                return value;
            }
        }
        return null;
    }
}
