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

    private CarbonConfigResolver() {

    }

    /**
     * Returns the Carbon config directory path. Uses CarbonUtils.getCarbonConfigDirPath() when the
     * carbon.utils bundle is available (optional OSGi dependency). Falls back to the "carbon.config.dir"
     * system property for environments like Micro Integrator that run without Carbon Kernel.
     *
     * @return the Carbon config directory path.
     * @throws IllegalStateException if neither CarbonUtils nor the system property is available.
     */
    public static String getCarbonConfigDirPath() {

        try {
            return CarbonUtils.getCarbonConfigDirPath();
        } catch (NoClassDefFoundError e) {
            String configDir = System.getProperty("carbon.config.dir");
            if (configDir != null) {
                configDir = configDir.trim();
                if (!configDir.isEmpty()) {
                    return configDir;
                }
            }
            throw new IllegalStateException(
                    "Cannot resolve Carbon config directory: carbon.utils bundle is not available " +
                    "and 'carbon.config.dir' system property is not set.", e);
        }
    }
}
