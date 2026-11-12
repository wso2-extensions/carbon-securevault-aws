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

package org.wso2.carbon.securevault.aws.secret.repository;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.securevault.aws.common.AWSSecretManagerClient;
import org.wso2.carbon.securevault.aws.common.AWSVaultUtils;
import org.wso2.carbon.securevault.aws.exception.AWSVaultRuntimeException;
import org.wso2.securevault.BaseCipher;
import org.wso2.securevault.CipherFactory;
import org.wso2.securevault.definition.CipherInformation;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ALGORITHM;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ENCRYPTION_ENABLED;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ROOT_PASSWORDS;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.SECRET_NAME_PREFIX;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.VERSION_DELIMITER;

/**
 * Unit test class for AWSSecretRepository with full coverage using Mockito.
 */
public class AWSSecretRepositoryTest {

    private static final String SECRET_NAME = "testSecret";
    private static final String SECRET_VALUE = "secretValue";
    private static final String SECRET_VERSION = "version1";

    @Mock
    private SecretsManagerClient secretsManagerClient;
    @Mock
    private SecretRepository parentRepository;
    @Mock
    private IdentityKeyStoreWrapper identityKeyStoreWrapper;
    @Mock
    private TrustKeyStoreWrapper trustKeyStoreWrapper;
    @Mock
    private BaseCipher baseCipher;

    private AWSSecretRepository awsSecretRepository;
    private AutoCloseable mocks;

    @BeforeMethod
    public void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        awsSecretRepository = new AWSSecretRepository();
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (mocks != null) {
            mocks.close();
        }
    }

    // Helper method to initialize repository with mocked client
    private void initRepository(Properties properties, String id, String encryptionEnabled) {

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            if (encryptionEnabled != null) {
                mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                        .thenReturn(encryptionEnabled);
            }
            awsSecretRepository.init(properties, id);
        }
    }

    // Helper method to setup secret response
    private void setupSecretResponse(String secretValue) {

        GetSecretValueResponse response = GetSecretValueResponse.builder()
                .secretString(secretValue)
                .build();
        when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(response);
    }

    @Test(description = "Test init method for secret retrieval")
    public void testInitForSecretRetrieval() {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("false");
            awsSecretRepository.init(properties, "testId");
            mockedClient.verify(() -> AWSSecretManagerClient.getInstance(properties), times(1));
        }
    }

    @Test(description = "Test init method for root password retrieval")
    public void testInitForRootPasswordRetrieval() {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            awsSecretRepository.init(properties, ROOT_PASSWORDS);
            mockedClient.verify(() -> AWSSecretManagerClient.getInstance(properties), times(1));
        }
    }

    @Test(description = "Test getSecret with valid secret name")
    public void testGetSecretWithValidName() {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("false");
            setupSecretResponse(SECRET_VALUE);
            awsSecretRepository.init(properties, "testId");
            assertEquals(awsSecretRepository.getSecret(SECRET_NAME), SECRET_VALUE);
            verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getSecret with secret name and version")
    public void testGetSecretWithNameAndVersion() {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("false");
            setupSecretResponse(SECRET_VALUE);
            awsSecretRepository.init(properties, "testId");
            assertEquals(awsSecretRepository.getSecret(SECRET_NAME + VERSION_DELIMITER + SECRET_VERSION), SECRET_VALUE);
            verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getSecret with empty/null names returns empty string", 
          dataProvider = "emptyNamesProvider")
    public void testGetSecretWithEmptyOrNullName(String secretName, String expected) {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("false");
            awsSecretRepository.init(properties, "testId");
            assertEquals(awsSecretRepository.getSecret(secretName), expected);
            verify(secretsManagerClient, never()).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @DataProvider(name = "emptyNamesProvider")
    public Object[][] emptyNamesProvider() {
        return new Object[][] { {"", ""}, {null, ""} };
    }

    @Test(description = "Test getSecret with invalid delimiters", dataProvider = "invalidDelimitersProvider")
    public void testGetSecretWithInvalidDelimiters(String alias) {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("false");
            awsSecretRepository.init(properties, "testId");
            assertEquals(awsSecretRepository.getSecret(alias), "");
            verify(secretsManagerClient, never()).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @DataProvider(name = "invalidDelimitersProvider")
    public Object[][] invalidDelimitersProvider() {
        return new Object[][] {
            {"secret#version#extra"},  // Multiple delimiters
            {VERSION_DELIMITER + SECRET_NAME}  // Delimiter at beginning
        };
    }

    @Test(description = "Test getSecret with empty version")
    public void testGetSecretWithEmptyVersion() {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("false");
            setupSecretResponse(SECRET_VALUE);
            awsSecretRepository.init(properties, "testId");
            assertEquals(awsSecretRepository.getSecret(SECRET_NAME + VERSION_DELIMITER), SECRET_VALUE);
            verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getSecret with exceptions", dataProvider = "exceptionsProvider")
    public void testGetSecretWithExceptions(Class<? extends Exception> exceptionClass) {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("false");
            if (exceptionClass == SdkClientException.class) {
                when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                        .thenThrow(SdkClientException.create("AWS SDK Error", new RuntimeException()));
            } else {
                when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                        .thenThrow(exceptionClass);
            }
            awsSecretRepository.init(properties, "testId");
            assertEquals(awsSecretRepository.getSecret(SECRET_NAME), "");
            verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @DataProvider(name = "exceptionsProvider")
    public Object[][] exceptionsProvider() {
        return new Object[][] {
            {ResourceNotFoundException.class},
            {SdkClientException.class}
        };
    }

    @Test(description = "Test getSecret when secret value is null or empty", dataProvider = "nullEmptyProvider")
    public void testGetSecretWithNullOrEmptyValue(String secretValue, String expected) {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("false");
            setupSecretResponse(secretValue);
            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret(SECRET_NAME);
            if (expected == null) {
                assertNull(result);
            } else {
                assertEquals(result, expected);
            }
            verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @DataProvider(name = "nullEmptyProvider")
    public Object[][] nullEmptyProvider() {
        return new Object[][] { {null, null}, {"", ""} };
    }

    @Test(description = "Test getEncryptedData throws UnsupportedOperationException when encryption is disabled",
            expectedExceptions = UnsupportedOperationException.class)
    public void testGetEncryptedDataWhenEncryptionDisabled() {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("false");
            awsSecretRepository.init(properties, "testId");
            awsSecretRepository.getEncryptedData(SECRET_NAME);
        }
    }

    @Test(description = "Test parent repository methods")
    public void testParentRepositoryMethods() {

        assertNull(awsSecretRepository.getParent());
        awsSecretRepository.setParent(parentRepository);
        assertEquals(awsSecretRepository.getParent(), parentRepository);
        awsSecretRepository.setParent(null);
        assertNull(awsSecretRepository.getParent());
    }

    @Test(description = "Test init with encryption property variations", dataProvider = "encryptionPropertyProvider")
    public void testInitWithEncryptionPropertyVariations(String encryptionValue) {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn(encryptionValue);
            awsSecretRepository.init(properties, "testId");
            mockedClient.verify(() -> AWSSecretManagerClient.getInstance(properties), times(1));
        }
    }

    @DataProvider(name = "encryptionPropertyProvider")
    public Object[][] encryptionPropertyProvider() {
        return new Object[][] { {null}, {""} };
    }

    @Test(description = "Test constructors")
    public void testConstructors() {
        assertNotNull(new AWSSecretRepository());
        assertNotNull(new AWSSecretRepository(null, null));
    }

    // Helper method for encryption tests
    private AWSSecretRepository setupEncryptionTest(Properties properties, String algorithm, 
                                                     String encryptedValue, String decryptedValue) {

        AWSSecretRepository repo = new AWSSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class);
             MockedStatic<CipherFactory> mockedCipher = mockStatic(CipherFactory.class)) {
            
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("true");
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ALGORITHM)).thenReturn(algorithm);
            mockedCipher.when(() -> CipherFactory.createCipher(any(CipherInformation.class),
                    any(IdentityKeyStoreWrapper.class))).thenReturn(baseCipher);
            when(baseCipher.decrypt(any(byte[].class)))
                    .thenReturn(decryptedValue.getBytes(StandardCharsets.UTF_8));
            setupSecretResponse(encryptedValue);
            repo.init(properties, "testId");
        }
        return repo;
    }

    @Test(description = "Test getSecret with encryption enabled", dataProvider = "encryptionAlgorithmProvider")
    public void testGetSecretWithEncryption(String algorithm) {

        Properties properties = new Properties();
        String encryptedValue = "ZW5jcnlwdGVk";
        String decryptedValue = "decrypted";
        
        AWSSecretRepository repo = setupEncryptionTest(properties, algorithm, encryptedValue, decryptedValue);
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            assertEquals(repo.getSecret(SECRET_NAME), decryptedValue);
            verify(baseCipher, times(1)).decrypt(any(byte[].class));
        }
    }

    @DataProvider(name = "encryptionAlgorithmProvider")
    public Object[][] encryptionAlgorithmProvider() {
        return new Object[][] { {"RSA"}, {null}, {"AES"} };  // null tests default algorithm
    }

    @Test(description = "Test encryption enabled throws exception when keystore is null",
            expectedExceptions = AWSVaultRuntimeException.class,
            expectedExceptionsMessageRegExp = ".*Key Store has not been initialized.*")
    public void testEncryptionEnabledWithoutKeystore() {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("true");
            awsSecretRepository.init(properties, "testId");
        }
    }

    @Test(description = "Test getEncryptedData with encryption enabled")
    public void testGetEncryptedDataWithEncryptionEnabled() {

        Properties properties = new Properties();
        String encryptedValue = "encryptedSecretValue";
        
        AWSSecretRepository repo = setupEncryptionTest(properties, "RSA", encryptedValue, "decrypted");
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            assertEquals(repo.getEncryptedData(SECRET_NAME), encryptedValue);
            verify(baseCipher, never()).decrypt(any(byte[].class));  // No decryption for getEncryptedData
        }
    }

    @Test(description = "Test getEncryptedData returns empty string on exception")
    public void testGetEncryptedDataWithException() {
        
        Properties properties = new Properties();
        AWSSecretRepository repo = new AWSSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class);
             MockedStatic<CipherFactory> mockedCipher = mockStatic(CipherFactory.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("true");
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ALGORITHM)).thenReturn("RSA");
            mockedCipher.when(() -> CipherFactory.createCipher(any(CipherInformation.class),
                    any(IdentityKeyStoreWrapper.class))).thenReturn(baseCipher);
            repo.init(properties, "testId");
            assertEquals(repo.getEncryptedData(null), "");  // null triggers exception
        }
    }

    // Helper method to retrieve a secret with the given prefix configured and capture the request sent to AWS.
    private GetSecretValueRequest getSecretWithPrefix(String prefix, String id, String alias) {

        Properties properties = new Properties();
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("false");
            mockedUtils.when(() -> AWSVaultUtils.getOptionalProperty(properties, SECRET_NAME_PREFIX))
                    .thenReturn(prefix);
            setupSecretResponse(SECRET_VALUE);
            awsSecretRepository.init(properties, id);
            assertEquals(awsSecretRepository.getSecret(alias), SECRET_VALUE);
        }
        ArgumentCaptor<GetSecretValueRequest> captor = ArgumentCaptor.forClass(GetSecretValueRequest.class);
        verify(secretsManagerClient, times(1)).getSecretValue(captor.capture());
        return captor.getValue();
    }

    @Test(description = "Test getSecret applies the secret name prefix", dataProvider = "secretNamePrefixProvider")
    public void testGetSecretWithSecretNamePrefix(String prefix, String expectedSecretId) {

        GetSecretValueRequest request = getSecretWithPrefix(prefix, "testId", SECRET_NAME);
        assertEquals(request.secretId(), expectedSecretId);
        assertNull(request.versionId());
    }

    @DataProvider(name = "secretNamePrefixProvider")
    public Object[][] secretNamePrefixProvider() {
        return new Object[][] {
            {"dev/", "dev/" + SECRET_NAME},
            {"  prod/  ", "prod/" + SECRET_NAME},  // Surrounding whitespace is trimmed
            {"", SECRET_NAME},
            {"   ", SECRET_NAME},
            {null, SECRET_NAME}  // Property not set
        };
    }

    @Test(description = "Test getSecret applies the secret name prefix only to the name when a version is given")
    public void testGetSecretWithSecretNamePrefixAndVersion() {

        GetSecretValueRequest request = getSecretWithPrefix("dev/", "testId",
                SECRET_NAME + VERSION_DELIMITER + SECRET_VERSION);
        assertEquals(request.secretId(), "dev/" + SECRET_NAME);
        assertEquals(request.versionId(), SECRET_VERSION);
    }

    @Test(description = "Test the secret name prefix is not applied to root password retrieval")
    public void testSecretNamePrefixNotAppliedForRootPasswords() {

        GetSecretValueRequest request = getSecretWithPrefix("dev/", ROOT_PASSWORDS, SECRET_NAME);
        assertEquals(request.secretId(), SECRET_NAME);
    }

    @Test(description = "Test an alias cannot reach a secret outside the configured secret name prefix",
            dataProvider = "prefixEscapeAliasProvider")
    public void testSecretNamePrefixCannotBeEscaped(String alias, String expectedSecretId) {

        GetSecretValueRequest request = getSecretWithPrefix("dev/", "testId", alias);
        assertEquals(request.secretId(), expectedSecretId);
    }

    @DataProvider(name = "prefixEscapeAliasProvider")
    public Object[][] prefixEscapeAliasProvider() {
        return new Object[][] {
            {"../prod/" + SECRET_NAME, "dev/../prod/" + SECRET_NAME},  // No path normalization
            {"/prod/" + SECRET_NAME, "dev//prod/" + SECRET_NAME},
            {"prod/" + SECRET_NAME, "dev/prod/" + SECRET_NAME},
            // A full ARN is prefixed too, so it no longer identifies a secret outside the prefix.
            {"arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/" + SECRET_NAME,
                    "dev/arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/" + SECRET_NAME},
            {"*", "dev/*"}
        };
    }

    @Test(description = "Test the secret name prefix is applied to getEncryptedData as well")
    public void testGetEncryptedDataWithSecretNamePrefix() {

        Properties properties = new Properties();
        AWSSecretRepository repo = new AWSSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class);
             MockedStatic<CipherFactory> mockedCipher = mockStatic(CipherFactory.class)) {
            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties)).thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("true");
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ALGORITHM)).thenReturn("RSA");
            mockedUtils.when(() -> AWSVaultUtils.getOptionalProperty(properties, SECRET_NAME_PREFIX))
                    .thenReturn("dev/");
            mockedCipher.when(() -> CipherFactory.createCipher(any(CipherInformation.class),
                    any(IdentityKeyStoreWrapper.class))).thenReturn(baseCipher);
            setupSecretResponse("encrypted");
            repo.init(properties, "testId");
            assertEquals(repo.getEncryptedData(SECRET_NAME), "encrypted");
        }
        ArgumentCaptor<GetSecretValueRequest> captor = ArgumentCaptor.forClass(GetSecretValueRequest.class);
        verify(secretsManagerClient, times(1)).getSecretValue(captor.capture());
        assertEquals(captor.getValue().secretId(), "dev/" + SECRET_NAME);
    }

    @Test(description = "Test a secret name prefix containing line breaks does not break secret retrieval flow")
    public void testSecretNamePrefixWithLineBreaks() {

        // Line breaks are stripped from log messages; the prefix itself is passed to AWS unchanged.
        GetSecretValueRequest request = getSecretWithPrefix("dev/\r\nFORGED", "testId", SECRET_NAME);
        assertEquals(request.secretId(), "dev/\r\nFORGED" + SECRET_NAME);
    }
}
