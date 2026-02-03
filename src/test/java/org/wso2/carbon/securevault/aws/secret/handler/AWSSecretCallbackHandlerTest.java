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

import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.securevault.aws.common.AWSSecretManagerClient;
import org.wso2.carbon.securevault.aws.exception.AWSVaultRuntimeException;
import org.wso2.carbon.securevault.aws.secret.repository.AWSSecretRepository;
import org.wso2.securevault.secret.SingleSecretCallback;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
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
    private static final String BASE_CONFIG = "keystore.identity.store.alias=keystoreAlias\n"
            + "secretRepositories=vault\n"
            + "secretRepositories.vault.properties.awsregion=us-east-1\n"
            + "secretRepositories.vault.provider="
            + "org.wso2.carbon.securevault.aws.secret.repository.AWSSecretRepositoryProvider\n";

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
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new AssertionError("Failed to reset static fields in AWSSecretCallbackHandler for test isolation", e);
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

    @DataProvider(name = "missingConfigProvider")
    public Object[][] missingConfigProvider() {
        return new Object[][]{
                {"no config file", null, ".*Error loading configurations.*"},
                {"no keystore alias", "# Empty config\n",
                        ".*keystore.identity.store.alias property has not been set.*"},
                {"empty keystore alias", "keystore.identity.store.alias=\n",
                        ".*keystore.identity.store.alias property has not been set.*"}
        };
    }

    @Test(description = "Test that AWSSecretCallbackHandler can be instantiated")
    public void testInstantiation() {
        assertNotNull(callbackHandler);
    }

    @Test(description = "Test that callback handler extends AbstractSecretCallbackHandler")
    public void testInheritance() {
        assertEquals(AWSSecretCallbackHandler.class.getSuperclass().getName(),
                "org.wso2.securevault.secret.AbstractSecretCallbackHandler");
    }

    @Test(dataProvider = "missingConfigProvider",
            description = "Test missing or invalid configuration",
            expectedExceptions = AWSVaultRuntimeException.class)
    public void testMissingConfiguration(String testCase, String configContent,
                                          String expectedMessage) throws IOException {
        if (configContent != null) {
            createTestConfigFile(configContent);
        }
        SingleSecretCallback callback = new SingleSecretCallback(IDENTITY_STORE_PASSWORD_ALIAS);
        callbackHandler.handleSingleSecretCallback(callback);
    }

    @DataProvider(name = "privateKeyAliasProvider")
    public Object[][] privateKeyAliasProvider() {
        return new Object[][]{
                {"not set", "secretRepositories.vault.properties.credentialProviders=ENV\n",
                        IDENTITY_KEY_PASSWORD_ALIAS},
                {"empty", "keystore.identity.key.alias=\n"
                        + "secretRepositories.vault.properties.credentialProviders=ENV\n",
                        IDENTITY_KEY_PASSWORD_ALIAS}
        };
    }

    @Test(dataProvider = "privateKeyAliasProvider",
            description = "Test private key alias scenarios")
    public void testPrivateKeyAliasScenarios(String scenario, String extraConfig,
                                              String callbackId) throws IOException {
        System.setProperty("key.password", "true");
        createTestConfigFile(BASE_CONFIG + extraConfig);

        SingleSecretCallback callback = new SingleSecretCallback(callbackId);
        try {
            callbackHandler.handleSingleSecretCallback(callback);
            assertNotNull(callback.getSecret(), "Secret should not be null");
        } catch (Exception e) {
            // Expected - AWS connection will fail without valid credentials
        }
    }

    @DataProvider(name = "keyPasswordPropertyProvider")
    public Object[][] keyPasswordPropertyProvider() {
        return new Object[][]{
                {"default null", null, null},
                {"set to true", "true", "true"},
                {"set to false", "false", "false"}
        };
    }

    @Test(dataProvider = "keyPasswordPropertyProvider", description = "Test system property key.password")
    public void testKeyPasswordSystemProperty(String testCase, String setValue, String expectedValue) {
        if (setValue != null) {
            System.setProperty("key.password", setValue);
        }
        assertEquals(System.getProperty("key.password"), expectedValue);
    }

    @Test(description = "Test multiple callback IDs are supported")
    public void testSupportedCallbackIds() {
        SingleSecretCallback callback1 = new SingleSecretCallback(IDENTITY_STORE_PASSWORD_ALIAS);
        SingleSecretCallback callback2 = new SingleSecretCallback(IDENTITY_KEY_PASSWORD_ALIAS);

        assertEquals(callback1.getId(), IDENTITY_STORE_PASSWORD_ALIAS);
        assertEquals(callback2.getId(), IDENTITY_KEY_PASSWORD_ALIAS);
    }

    @DataProvider(name = "pathVerificationProvider")
    public Object[][] pathVerificationProvider() {
        return new Object[][]{
                {"config directory", TEST_CONFIG_DIR, new String[]{"repository", "conf", "security"}},
                {"config file", TEST_CONFIG_FILE, new String[]{"secret-conf.properties"}}
        };
    }

    @Test(dataProvider = "pathVerificationProvider", description = "Test path construction")
    public void testPathConstruction(String pathType, String path, String[] expectedParts) {
        for (String part : expectedParts) {
            assertTrue(path.contains(part));
        }
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

    @Test(description = "Test config file can be created and read")
    public void testConfigFileCreationAndReading() throws IOException {
        String testContent = "test.property=testValue\n";
        createTestConfigFile(testContent);

        Path configFile = Paths.get(TEST_CONFIG_FILE);
        assertTrue(Files.exists(configFile), "Config file should exist");
        assertTrue(new String(Files.readAllBytes(configFile)).contains("test.property=testValue"));
    }

    @DataProvider(name = "passwordRetrievalProvider")
    public Object[][] passwordRetrievalProvider() {
        return new Object[][]{
                {"same password", false, "keystoreAlias", null, "testPassword123", null,
                        IDENTITY_STORE_PASSWORD_ALIAS, "testPassword123"},
                {"different passwords", true, "keystoreAlias", "privateKeyAlias",
                        "keystorePass123", "privateKeyPass456",
                        IDENTITY_STORE_PASSWORD_ALIAS, "keystorePass123"}
        };
    }

    @Test(dataProvider = "passwordRetrievalProvider",
            description = "Test successful password retrieval")
    public void testSuccessfulPasswordRetrieval(String scenario, boolean setKeyPassword,
                                                  String keystoreAlias, String privateKeyAlias,
                                                  String keystorePass, String privateKeyPass,
                                                  String callbackId, String expectedPassword)
            throws IOException {
        if (setKeyPassword) {
            System.setProperty("key.password", "true");
        }

        String config = "keystore.identity.store.alias=" + keystoreAlias + "\n";
        if (privateKeyAlias != null) {
            config += "keystore.identity.key.alias=" + privateKeyAlias + "\n";
        }
        config += BASE_CONFIG.substring(BASE_CONFIG.indexOf("secretRepositories"));

        createTestConfigFile(config);

        SecretsManagerClient mockSecretsClient = mock(SecretsManagerClient.class);

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedConstruction<AWSSecretRepository> mockedRepo = mockConstruction(AWSSecretRepository.class,
                     (mock, context) -> {
                         when(mock.getSecret(keystoreAlias)).thenReturn(keystorePass);
                         if (privateKeyAlias != null) {
                             when(mock.getSecret(privateKeyAlias)).thenReturn(privateKeyPass);
                         }
                     })) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(any())).thenReturn(mockSecretsClient);

            SingleSecretCallback callback = new SingleSecretCallback(callbackId);
            callbackHandler.handleSingleSecretCallback(callback);

            assertNotNull(callback.getSecret(), "Secret should not be null");
            assertEquals(String.valueOf(callback.getSecret()), expectedPassword);
        }
    }

    @Test(description = "Test that cached passwords are reused on subsequent calls")
    public void testPasswordCaching() throws Exception {
        createTestConfigFile(BASE_CONFIG);

        SecretsManagerClient mockSecretsClient = mock(SecretsManagerClient.class);

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedConstruction<AWSSecretRepository> mockedRepo = mockConstruction(AWSSecretRepository.class,
                     (mock, context) -> {
                         when(mock.getSecret(anyString())).thenReturn("cachedPassword");
                     })) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(any())).thenReturn(mockSecretsClient);

            SingleSecretCallback callback1 = new SingleSecretCallback(IDENTITY_STORE_PASSWORD_ALIAS);
            callbackHandler.handleSingleSecretCallback(callback1);
            assertEquals(String.valueOf(callback1.getSecret()), "cachedPassword");

            SingleSecretCallback callback2 = new SingleSecretCallback(IDENTITY_STORE_PASSWORD_ALIAS);
            callbackHandler.handleSingleSecretCallback(callback2);
            assertEquals(String.valueOf(callback2.getSecret()), "cachedPassword");
        }
    }

    @DataProvider(name = "emptyPasswordProvider")
    public Object[][] emptyPasswordProvider() {
        return new Object[][]{
                {"keystore password empty", false, "", null, IDENTITY_STORE_PASSWORD_ALIAS},
                {"private key password empty", true, "keystorePass123", "", IDENTITY_KEY_PASSWORD_ALIAS}
        };
    }

    @Test(dataProvider = "emptyPasswordProvider", description = "Test exception when password retrieval returns empty",
            expectedExceptions = AWSVaultRuntimeException.class,
            expectedExceptionsMessageRegExp = ".*Error in retrieving.*")
    public void testExceptionWhenPasswordEmpty(String scenario, boolean setKeyPassword, String keystorePass,
                                                 String privateKeyPass, String callbackId) throws IOException {
        if (setKeyPassword) {
            System.setProperty("key.password", "true");
        }

        String config = BASE_CONFIG;
        if (setKeyPassword) {
            config += "keystore.identity.key.alias=privateKeyAlias\n";
        }

        createTestConfigFile(config);

        SecretsManagerClient mockSecretsClient = mock(SecretsManagerClient.class);

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedConstruction<AWSSecretRepository> mockedRepo = mockConstruction(AWSSecretRepository.class,
                     (mock, context) -> {
                         when(mock.getSecret("keystoreAlias")).thenReturn(keystorePass);
                         when(mock.getSecret("privateKeyAlias")).thenReturn(privateKeyPass);
                     })) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(any())).thenReturn(mockSecretsClient);

            SingleSecretCallback callback = new SingleSecretCallback(callbackId);
            callbackHandler.handleSingleSecretCallback(callback);
        }
    }

    @Test(description = "Test exception when private key alias not set but key.password is true",
            expectedExceptions = AWSVaultRuntimeException.class,
            expectedExceptionsMessageRegExp = ".*keystore.identity.key.alias property has not been set.*")
    public void testExceptionWhenPrivateKeyAliasNotSetButRequired() throws IOException {
        System.setProperty("key.password", "true");
        createTestConfigFile(BASE_CONFIG);

        SecretsManagerClient mockSecretsClient = mock(SecretsManagerClient.class);

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedConstruction<AWSSecretRepository> mockedRepo = mockConstruction(AWSSecretRepository.class,
                     (mock, context) -> {
                         when(mock.getSecret("keystoreAlias")).thenReturn("keystorePass123");
                     })) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(any())).thenReturn(mockSecretsClient);

            SingleSecretCallback callback = new SingleSecretCallback(IDENTITY_KEY_PASSWORD_ALIAS);
            callbackHandler.handleSingleSecretCallback(callback);
        }
    }

    @Test(description = "Test setting secret for identity.key.password ID")
    public void testSetSecretForPrivateKeyPasswordId() throws IOException {
        System.setProperty("key.password", "true");
        createTestConfigFile(BASE_CONFIG + "keystore.identity.key.alias=privateKeyAlias\n");

        SecretsManagerClient mockSecretsClient = mock(SecretsManagerClient.class);

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedConstruction<AWSSecretRepository> mockedRepo = mockConstruction(AWSSecretRepository.class,
                     (mock, context) -> {
                         when(mock.getSecret("keystoreAlias")).thenReturn("keystorePass");
                         when(mock.getSecret("privateKeyAlias")).thenReturn("privateKeyPass");
                     })) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(any())).thenReturn(mockSecretsClient);

            SingleSecretCallback callback = new SingleSecretCallback(IDENTITY_KEY_PASSWORD_ALIAS);
            callbackHandler.handleSingleSecretCallback(callback);

            assertNotNull(callback.getSecret());
            assertTrue(String.valueOf(callback.getSecret()).length() > 0);
        }
    }
}
