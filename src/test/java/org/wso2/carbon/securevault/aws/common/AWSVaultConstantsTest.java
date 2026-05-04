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
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.utils.CarbonUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Unit tests for the config-directory resolution logic in AWSVaultConstants.
 */
public class AWSVaultConstantsTest {

    private static final String CONFIG_DIR_PROPERTY = "carbon.config.dir";
    private static final String TEST_CONFIG_DIR = "/test/conf";

    @BeforeClass
    public void initAWSVaultConstants() {

        // AWSVaultConstants.CONFIG_FILE_PATH is a static final evaluated once at class init.
        // This access forces initialization now, before any test mocks are active, so that
        // subsequent mocking of CarbonUtils cannot permanently corrupt the constant's value.
        System.setProperty("carbon.home", System.getProperty("java.io.tmpdir"));
        AWSVaultConstants.CONFIG_FILE_PATH.length();
    }

    @AfterClass
    public void cleanUp() {

        System.clearProperty("carbon.home");
    }

    @AfterMethod
    public void clearSystemProperty() {

        System.clearProperty(CONFIG_DIR_PROPERTY);
    }

    @Test(description = "When CarbonUtils is unavailable, the carbon.config.dir system property is used as fallback")
    public void testFallbackToSystemPropertyWhenCarbonUtilsUnavailable() throws Exception {

        System.setProperty(CONFIG_DIR_PROPERTY, TEST_CONFIG_DIR);

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            assertEquals(invokeCarbonConfigDirPath(), TEST_CONFIG_DIR);
        }
    }

    @Test(description = "System property value with surrounding whitespace is trimmed before use")
    public void testSystemPropertyValueIsTrimmed() throws Exception {

        System.setProperty(CONFIG_DIR_PROPERTY, "  " + TEST_CONFIG_DIR + "  ");

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            assertEquals(invokeCarbonConfigDirPath(), TEST_CONFIG_DIR);
        }
    }

    @Test(description = "When neither CarbonUtils nor system property is available, IllegalStateException is thrown")
    public void testIllegalStateExceptionWhenNeitherSourceAvailable() throws Exception {

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            assertIllegalStateException();
        }
    }

    @Test(description = "When CarbonUtils is unavailable and system property is blank, IllegalStateException is thrown")
    public void testIllegalStateExceptionWhenSystemPropertyIsBlank() throws Exception {

        System.setProperty(CONFIG_DIR_PROPERTY, "   ");

        try (MockedStatic<CarbonUtils> carbonUtils = mockStatic(CarbonUtils.class)) {
            carbonUtils.when(CarbonUtils::getCarbonConfigDirPath)
                       .thenThrow(new NoClassDefFoundError("org/wso2/carbon/utils/CarbonUtils"));

            assertIllegalStateException();
        }
    }

    private void assertIllegalStateException() throws Exception {

        try {
            invokeCarbonConfigDirPath();
            fail("Expected IllegalStateException to be thrown");
        } catch (InvocationTargetException e) {
            assertTrue(e.getCause() instanceof IllegalStateException,
                    "Expected IllegalStateException but was: " + e.getCause().getClass().getName());
        }
    }

    private String invokeCarbonConfigDirPath() throws Exception {

        Method method = AWSVaultConstants.class.getDeclaredMethod("getCarbonConfigDirPath");
        method.setAccessible(true);
        return (String) method.invoke(null);
    }
}
