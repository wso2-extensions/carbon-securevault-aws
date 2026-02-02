/*
 * Copyright (c) 2022-2026, WSO2 LLC (http://www.wso2.com).
 *
 * WSO2 LLC licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.securevault.aws.common;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.lang.reflect.Field;
import java.util.Properties;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/**
 * Unit test class for AWSVaultUtils with full coverage.
 */
public class AWSVaultUtilsTest {

    private static final String TEST_PROPERTY_VALUE = "testValue";
    private static final String SECRET_REPOSITORIES = "secretRepositories";
    private static final String SECRET_PROVIDERS = "secretProviders";

    @BeforeMethod
    public void setUp() {
        resetPropertiesPrefix();
    }

    @AfterMethod
    public void tearDown() {
        resetPropertiesPrefix();
    }

    /**
     * Reset the static propertiesPrefix field to ensure test isolation.
     */
    private void resetPropertiesPrefix() {
        try {
            Field field = AWSVaultUtils.class.getDeclaredField("propertiesPrefix");
            field.setAccessible(true);
            synchronized (AWSVaultUtils.class) {
                field.set(null, null);
            }
        } catch (Exception e) {
            // Fail silently - field reset is for test isolation
        }
    }

    @DataProvider(name = "configFormats")
    public Object[][] configFormatsData() {
        return new Object[][] {
            { SECRET_REPOSITORIES, "secretRepositories.vault.properties.", "legacy" },
            { SECRET_PROVIDERS, "secretProviders.vault.repositories.aws.properties.", "novel" }
        };
    }

    @DataProvider(name = "multipleProperties")
    public Object[][] multiplePropertiesData() {
        return new Object[][] {
            { "prop1", "value1" },
            { "prop2", "value2" },
            { "prop3", "value3" }
        };
    }

    @Test(description = "Test getProperty with different configuration formats",
          dataProvider = "configFormats")
    public void testGetPropertyWithConfigFormats(String configType, String prefix, String description) {
        Properties properties = new Properties();
        properties.setProperty(configType, "vault");
        properties.setProperty(prefix + "testProperty", TEST_PROPERTY_VALUE);

        String result = AWSVaultUtils.getProperty(properties, "testProperty");

        assertEquals(result, TEST_PROPERTY_VALUE, "Should retrieve property with " + description + " format");
    }

    @Test(description = "Test getProperty with multiple properties",
          dataProvider = "configFormats")
    public void testMultipleProperties(String configType, String prefix, String description) {
        Properties properties = new Properties();
        properties.setProperty(configType, "vault");
        properties.setProperty(prefix + "prop1", "value1");
        properties.setProperty(prefix + "prop2", "value2");
        properties.setProperty(prefix + "prop3", "value3");

        assertEquals(AWSVaultUtils.getProperty(properties, "prop1"), "value1");
        assertEquals(AWSVaultUtils.getProperty(properties, "prop2"), "value2");
        assertEquals(AWSVaultUtils.getProperty(properties, "prop3"), "value3");
    }

    @Test(description = "Test getProperty when properties prefix is already cached")
    public void testGetPropertyWithCachedPrefix() {
        Properties properties = new Properties();
        properties.setProperty(SECRET_PROVIDERS, "vault");
        properties.setProperty("secretProviders.vault.repositories.aws.properties.property1", "value1");
        properties.setProperty("secretProviders.vault.repositories.aws.properties.property2", "value2");

        String result1 = AWSVaultUtils.getProperty(properties, "property1");
        String result2 = AWSVaultUtils.getProperty(properties, "property2");

        assertEquals(result1, "value1");
        assertEquals(result2, "value2");
    }

    @Test(description = "Test getProperty when property does not exist")
    public void testGetPropertyWhenPropertyNotFound() {
        Properties properties = new Properties();
        properties.setProperty(SECRET_PROVIDERS, "vault");

        String result = AWSVaultUtils.getProperty(properties, "nonExistentProperty");

        assertNull(result);
    }

    @Test(description = "Test getProperty with null properties throws IllegalArgumentException",
            expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Properties cannot be null.")
    public void testGetPropertyWithNullProperties() {
        AWSVaultUtils.getProperty(null, "testProperty");
    }

    @Test(description = "Test getProperty with empty property name returns null")
    public void testGetPropertyWithEmptyPropertyName() {
        Properties properties = new Properties();
        properties.setProperty(SECRET_PROVIDERS, "vault");

        assertNull(AWSVaultUtils.getProperty(properties, ""));
    }

    @Test(description = "Test getProperty with null property name throws NullPointerException",
            expectedExceptions = NullPointerException.class)
    public void testGetPropertyWithNullPropertyName() {
        Properties properties = new Properties();
        properties.setProperty(SECRET_PROVIDERS, "vault");

        AWSVaultUtils.getProperty(properties, null);
    }

    @Test(description = "Test property with special characters in name")
    public void testGetPropertyWithSpecialCharacters() {
        Properties properties = new Properties();
        properties.setProperty(SECRET_PROVIDERS, "vault");
        properties.setProperty("secretProviders.vault.repositories.aws.properties.test.property.with.dots",
                TEST_PROPERTY_VALUE);

        assertEquals(AWSVaultUtils.getProperty(properties, "test.property.with.dots"), TEST_PROPERTY_VALUE);
    }

    @Test(description = "Test sequential calls with different property types")
    public void testSequentialCallsWithDifferentConfigTypes() {
        resetPropertiesPrefix();

        Properties legacyProps = new Properties();
        legacyProps.setProperty(SECRET_REPOSITORIES, "vault");
        legacyProps.setProperty("secretRepositories.vault.properties.legacyProp", "legacyValue");

        assertEquals(AWSVaultUtils.getProperty(legacyProps, "legacyProp"), "legacyValue");

        resetPropertiesPrefix();

        Properties novelProps = new Properties();
        novelProps.setProperty(SECRET_PROVIDERS, "vault");
        novelProps.setProperty("secretProviders.vault.repositories.aws.properties.novelProp", "novelValue");

        assertEquals(AWSVaultUtils.getProperty(novelProps, "novelProp"), "novelValue");
    }

    @Test(description = "Test synchronized access to propertiesPrefix")
    public void testSynchronizedPrefixAccess() {
        resetPropertiesPrefix();

        Properties properties = new Properties();
        properties.setProperty(SECRET_PROVIDERS, "vault");
        properties.setProperty("secretProviders.vault.repositories.aws.properties.test", "value");

        for (int i = 0; i < 10; i++) {
            assertEquals(AWSVaultUtils.getProperty(properties, "test"), "value");
        }
    }

    @Test(description = "Test properties with empty secret repositories value")
    public void testPropertiesWithEmptySecretRepositories() {
        Properties properties = new Properties();
        properties.setProperty(SECRET_REPOSITORIES, "");
        properties.setProperty("secretProviders.vault.repositories.aws.properties.test", TEST_PROPERTY_VALUE);

        assertEquals(AWSVaultUtils.getProperty(properties, "test"), TEST_PROPERTY_VALUE);
    }
}
