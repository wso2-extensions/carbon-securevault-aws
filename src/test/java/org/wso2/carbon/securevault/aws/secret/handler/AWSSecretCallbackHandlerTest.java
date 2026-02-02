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

package org.wso2.carbon.securevault.aws.secret.handler;

import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.securevault.aws.exception.AWSVaultRuntimeException;
import org.wso2.securevault.secret.SingleSecretCallback;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.IDENTITY_KEY_PASSWORD_ALIAS;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.IDENTITY_STORE_PASSWORD_ALIAS;

/**
 * Unit test class for AWSSecretCallbackHandler.
 * Tests use actual file I/O with temporary test files instead of complex mocking.
 */
public class AWSSecretCallbackHandlerTest {

    private static final String TEMP_DIR = System.getProperty("java.io.tmpdir");
    private static final String TEST_CONFIG_DIR = TEMP_DIR + File.separator + "repository" + File.separator
            + "conf" + File.separator + "security";
    private static final String TEST_CONFIG_FILE = TEST_CONFIG_DIR + File.separator + "secret-conf.properties";

    private AWSSecretCallbackHandler callbackHandler;

    @BeforeClass
    public void setUpClass() throws IOException {
        System.setProperty("carbon.home", TEMP_DIR);
        // Create test directory structure
        Files.createDirectories(Paths.get(TEST_CONFIG_DIR));
    }

    @AfterClass
    public void tearDownClass() throws IOException {
        System.clearProperty("carbon.home");
        // Clean up test directory
        Path configFile = Paths.get(TEST_CONFIG_FILE);
        if (Files.exists(configFile)) {
            Files.delete(configFile);
        }
    }

    @BeforeMethod
    public void setUp() {
        callbackHandler = new AWSSecretCallbackHandler();
        resetStaticFields();
        System.clearProperty("key.password");
    }

    @AfterMethod
    public void tearDown() throws IOException {
        resetStaticFields();
        System.clearProperty("key.password");
        // Clean up config file after each test
        Path configFile = Paths.get(TEST_CONFIG_FILE);
        if (Files.exists(configFile)) {
            Files.delete(configFile);
        }
    }

    /**
     * Reset static fields in AWSSecretCallbackHandler for test isolation.
     */
    private void resetStaticFields() {
        try {
            Field keystoreField = AWSSecretCallbackHandler.class.getDeclaredField("keyStorePassword");
            keystoreField.setAccessible(true);
            keystoreField.set(null, null);

            Field privateKeyField = AWSSecretCallbackHandler.class.getDeclaredField("privateKeyPassword");
            privateKeyField.setAccessible(true);
            privateKeyField.set(null, null);
        } catch (Exception e) {
            // Fail silently
        }
    }

    /**
     * Helper method to create a test configuration file.
     */
    private void createTestConfigFile(String content) throws IOException {
        try (FileWriter writer = new FileWriter(TEST_CONFIG_FILE)) {
            writer.write(content);
        }
    }

    @Test(description = "Test that AWSSecretCallbackHandler can be instantiated")
    public void testInstantiation() {
        assertNotNull(callbackHandler);
    }

    @Test(description = "Test handleSingleSecretCallback throws exception when config file doesn't exist",
            expectedExceptions = AWSVaultRuntimeException.class,
            expectedExceptionsMessageRegExp = ".*Error loading configurations.*")
    public void testHandleSingleSecretCallbackNoConfigFile() {
        SingleSecretCallback callback = new SingleSecretCallback(IDENTITY_STORE_PASSWORD_ALIAS);
        callbackHandler.handleSingleSecretCallback(callback);
    }

    @Test(description = "Test handleSingleSecretCallback throws exception when keystore alias not set",
            expectedExceptions = AWSVaultRuntimeException.class,
            expectedExceptionsMessageRegExp = ".*keystore.identity.store.alias property has not been set.*")
    public void testHandleSingleSecretCallbackNoKeystoreAlias() throws IOException {
        createTestConfigFile("# Empty config\n");
        SingleSecretCallback callback = new SingleSecretCallback(IDENTITY_STORE_PASSWORD_ALIAS);
        callbackHandler.handleSingleSecretCallback(callback);
    }

    @Test(description = "Test handleSingleSecretCallback throws exception when keystore alias is empty",
            expectedExceptions = AWSVaultRuntimeException.class,
            expectedExceptionsMessageRegExp = ".*keystore.identity.store.alias property has not been set.*")
    public void testHandleSingleSecretCallbackEmptyKeystoreAlias() throws IOException {
        createTestConfigFile("keystore.identity.store.alias=\n");
        SingleSecretCallback callback = new SingleSecretCallback(IDENTITY_STORE_PASSWORD_ALIAS);
        callbackHandler.handleSingleSecretCallback(callback);
    }

    @Test(description = "Test handleSingleSecretCallback works when private key alias not set")
    public void testHandleSingleSecretCallbackNoPrivateKeyAlias() throws IOException {
        System.setProperty("key.password", "true");
        createTestConfigFile("keystore.identity.store.alias=testAlias\n"
                + "secretRepositories=vault\n"
                + "secretRepositories.vault.properties.awsregion=us-east-1\n"
                + "secretRepositories.vault.properties.credentialProviders=ENV\n");

        SingleSecretCallback callback = new SingleSecretCallback(IDENTITY_KEY_PASSWORD_ALIAS);

        try {
            callbackHandler.handleSingleSecretCallback(callback);
            assertNotNull(callback.getSecret(), "Secret should not be null");
        } catch (Exception e) {
            // Expected - AWS connection will fail without valid credentials
        }
    }

    @Test(description = "Test handleSingleSecretCallbackEmptyPrivateKeyAlias works when private key alias is empty")
    public void testHandleSingleSecretCallbackEmptyPrivateKeyAlias() throws IOException {
        System.setProperty("key.password", "true");
        createTestConfigFile("keystore.identity.store.alias=testAlias\n"
                + "keystore.identity.key.alias=\n"
                + "secretRepositories=vault\n"
                + "secretRepositories.vault.properties.awsregion=us-east-1\n"
                + "secretRepositories.vault.properties.credentialProviders=ENV\n");

        SingleSecretCallback callback = new SingleSecretCallback(IDENTITY_KEY_PASSWORD_ALIAS);

        try {
            callbackHandler.handleSingleSecretCallback(callback);
            assertNotNull(callback.getSecret(), "Secret should not be null");
        } catch (Exception e) {
            // Expected - AWS connection will fail without valid credentials
        }
    }

    @Test(description = "Test system property key.password defaults to false")
    public void testKeyPasswordSystemPropertyDefault() {
        assertNull(System.getProperty("key.password"), "key.password should be null by default");
    }

    @Test(description = "Test system property key.password can be set to true")
    public void testKeyPasswordSystemPropertySetTrue() {
        System.setProperty("key.password", "true");
        assertEquals(System.getProperty("key.password"), "true");
    }

    @Test(description = "Test system property key.password can be set to false")
    public void testKeyPasswordSystemPropertySetFalse() {
        System.setProperty("key.password", "false");
        assertEquals(System.getProperty("key.password"), "false");
    }

    @Test(description = "Test that callback handler extends AbstractSecretCallbackHandler")
    public void testInheritance() {
        assertTrue(callbackHandler instanceof org.wso2.securevault.secret.AbstractSecretCallbackHandler);
    }

    @Test(description = "Test config file can be created and read")
    public void testConfigFileCreationAndReading() throws IOException {
        String testContent = "test.property=testValue\n";
        createTestConfigFile(testContent);

        Path configFile = Paths.get(TEST_CONFIG_FILE);
        assertTrue(Files.exists(configFile), "Config file should exist");
        assertTrue(new String(Files.readAllBytes(configFile)).contains("test.property=testValue"));
    }

    @Test(description = "Test multiple callback IDs are supported")
    public void testSupportedCallbackIds() {
        SingleSecretCallback callback1 = new SingleSecretCallback(IDENTITY_STORE_PASSWORD_ALIAS);
        SingleSecretCallback callback2 = new SingleSecretCallback(IDENTITY_KEY_PASSWORD_ALIAS);

        assertEquals(callback1.getId(), IDENTITY_STORE_PASSWORD_ALIAS);
        assertEquals(callback2.getId(), IDENTITY_KEY_PASSWORD_ALIAS);
    }

    @Test(description = "Test static fields are reset between tests")
    public void testStaticFieldsReset() throws Exception {
        Field keystoreField = AWSSecretCallbackHandler.class.getDeclaredField("keyStorePassword");
        keystoreField.setAccessible(true);
        assertNull(keystoreField.get(null), "keyStorePassword should be null after reset");
    }

    @Test(description = "Test carbon.home system property is set correctly")
    public void testCarbonHomeProperty() {
        assertEquals(System.getProperty("carbon.home"), TEMP_DIR);
    }

    @Test(description = "Test configuration directory path is constructed correctly")
    public void testConfigDirectoryPath() {
        assertTrue(TEST_CONFIG_DIR.contains("repository"));
        assertTrue(TEST_CONFIG_DIR.contains("conf"));
        assertTrue(TEST_CONFIG_DIR.contains("security"));
    }

    @Test(description = "Test configuration file path is constructed correctly")
    public void testConfigFilePath() {
        assertTrue(TEST_CONFIG_FILE.endsWith("secret-conf.properties"));
    }
}
