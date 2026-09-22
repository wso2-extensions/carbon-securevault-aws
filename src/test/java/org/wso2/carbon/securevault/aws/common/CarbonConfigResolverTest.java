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

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.utils.CarbonUtils;

import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;

/**
 * Unit tests for CarbonConfigResolver.
 */
public class CarbonConfigResolverTest {

    private static final String CONFIG_DIR_PROPERTY = "carbon.config.dir";
    private static final String CONFIG_DIR_PATH_PROPERTY = "carbon.config.dir.path";
    private static final String TEST_CONFIG_DIR = "/test/conf";
    private static final String TEST_CONFIG_DIR_PATH = "/test/path/conf";

    @AfterMethod
    public void clearSystemProperty() {

        System.clearProperty(CONFIG_DIR_PROPERTY);
        System.clearProperty(CONFIG_DIR_PATH_PROPERTY);
    }

    @Test(description = "When CarbonUtils is unavailable, the carbon.config.dir system property is used as fallback")
    public void testFallbackToSystemPropertyWhenCarbonUtilsUnavailable() {

        System.setProperty(CONFIG_DIR_PROPERTY, TEST_CONFIG_DIR);

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            assertEquals(CarbonConfigResolver.getCarbonConfigDirPath(), TEST_CONFIG_DIR);
        }
    }

    @Test(description = "System property value with surrounding whitespace is trimmed before use")
    public void testSystemPropertyValueIsTrimmed() {

        System.setProperty(CONFIG_DIR_PROPERTY, "  " + TEST_CONFIG_DIR + "  ");

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            assertEquals(CarbonConfigResolver.getCarbonConfigDirPath(), TEST_CONFIG_DIR);
        }
    }

    @Test(description = "When neither CarbonUtils nor system property is available, IllegalStateException is thrown",
            expectedExceptions = IllegalStateException.class)
    public void testIllegalStateExceptionWhenNeitherSourceAvailable() {

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            CarbonConfigResolver.getCarbonConfigDirPath();
        }
    }

    @Test(description = "When CarbonUtils is unavailable and system property is blank, IllegalStateException is thrown",
            expectedExceptions = IllegalStateException.class)
    public void testIllegalStateExceptionWhenSystemPropertyIsBlank() {

        System.setProperty(CONFIG_DIR_PROPERTY, "   ");

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            CarbonConfigResolver.getCarbonConfigDirPath();
        }
    }

    @Test(description = "When CarbonUtils is unavailable and carbon.config.dir is not set, the "
            + "carbon.config.dir.path system property is used as fallback")
    public void testFallbackToConfigDirPathPropertyWhenConfigDirUnavailable() {

        System.setProperty(CONFIG_DIR_PATH_PROPERTY, TEST_CONFIG_DIR_PATH);

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            assertEquals(CarbonConfigResolver.getCarbonConfigDirPath(), TEST_CONFIG_DIR_PATH);
        }
    }

    @Test(description = "When both system properties are set, carbon.config.dir takes precedence")
    public void testConfigDirPropertyTakesPrecedenceOverConfigDirPath() {

        System.setProperty(CONFIG_DIR_PROPERTY, TEST_CONFIG_DIR);
        System.setProperty(CONFIG_DIR_PATH_PROPERTY, TEST_CONFIG_DIR_PATH);

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            assertEquals(CarbonConfigResolver.getCarbonConfigDirPath(), TEST_CONFIG_DIR);
        }
    }

    @Test(description = "When carbon.config.dir is blank, the carbon.config.dir.path system property is used")
    public void testFallbackToConfigDirPathPropertyWhenConfigDirIsBlank() {

        System.setProperty(CONFIG_DIR_PROPERTY, "   ");
        System.setProperty(CONFIG_DIR_PATH_PROPERTY, TEST_CONFIG_DIR_PATH);

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            assertEquals(CarbonConfigResolver.getCarbonConfigDirPath(), TEST_CONFIG_DIR_PATH);
        }
    }

    @Test(description = "carbon.config.dir.path value with surrounding whitespace is trimmed before use")
    public void testConfigDirPathPropertyValueIsTrimmed() {

        System.setProperty(CONFIG_DIR_PATH_PROPERTY, "  " + TEST_CONFIG_DIR_PATH + "  ");

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            assertEquals(CarbonConfigResolver.getCarbonConfigDirPath(), TEST_CONFIG_DIR_PATH);
        }
    }
}
