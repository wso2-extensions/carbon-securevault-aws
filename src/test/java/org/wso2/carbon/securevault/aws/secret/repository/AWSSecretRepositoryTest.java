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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.securevault.aws.common.AWSSecretManagerClient;
import org.wso2.carbon.securevault.aws.common.AWSVaultUtils;
import org.wso2.securevault.secret.SecretRepository;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

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
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ENCRYPTION_ENABLED;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ROOT_PASSWORDS;
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

    @Test(description = "Test init method for secret retrieval")
    public void testInitForSecretRetrieval() {
        Properties properties = new Properties();

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            awsSecretRepository.init(properties, "testId");

            mockedClient.verify(() -> AWSSecretManagerClient.getInstance(properties), times(1));
        }
    }

    @Test(description = "Test init method for root password retrieval")
    public void testInitForRootPasswordRetrieval() {
        Properties properties = new Properties();

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);

            awsSecretRepository.init(properties, ROOT_PASSWORDS);

            mockedClient.verify(() -> AWSSecretManagerClient.getInstance(properties), times(1));
        }
    }

    @Test(description = "Test getSecret with valid secret name")
    public void testGetSecretWithValidName() {
        Properties properties = new Properties();

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            GetSecretValueResponse response = GetSecretValueResponse.builder()
                    .secretString(SECRET_VALUE)
                    .build();
            when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                    .thenReturn(response);

            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret(SECRET_NAME);

            assertEquals(result, SECRET_VALUE);
            verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getSecret with secret name and version")
    public void testGetSecretWithNameAndVersion() {
        Properties properties = new Properties();
        String secretAlias = SECRET_NAME + VERSION_DELIMITER + SECRET_VERSION;

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            GetSecretValueResponse response = GetSecretValueResponse.builder()
                    .secretString(SECRET_VALUE)
                    .build();
            when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                    .thenReturn(response);

            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret(secretAlias);

            assertEquals(result, SECRET_VALUE);
            verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getSecret with empty secret name returns empty string")
    public void testGetSecretWithEmptyName() {
        Properties properties = new Properties();

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret("");

            assertEquals(result, "");
            verify(secretsManagerClient, never()).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getSecret with null secret name returns empty string")
    public void testGetSecretWithNullName() {
        Properties properties = new Properties();

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret(null);

            assertEquals(result, "");
            verify(secretsManagerClient, never()).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getSecret with multiple delimiters returns empty string")
    public void testGetSecretWithMultipleDelimiters() {
        Properties properties = new Properties();
        String invalidAlias = "secret#version#extra";

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret(invalidAlias);

            assertEquals(result, "");
            verify(secretsManagerClient, never()).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getSecret with empty version")
    public void testGetSecretWithEmptyVersion() {
        Properties properties = new Properties();
        String aliasWithEmptyVersion = SECRET_NAME + VERSION_DELIMITER;

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            GetSecretValueResponse response = GetSecretValueResponse.builder()
                    .secretString(SECRET_VALUE)
                    .build();
            when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                    .thenReturn(response);

            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret(aliasWithEmptyVersion);

            assertEquals(result, SECRET_VALUE);
            verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getSecret when ResourceNotFoundException is thrown returns empty string")
    public void testGetSecretWithResourceNotFoundException() {
        Properties properties = new Properties();

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                    .thenThrow(ResourceNotFoundException.class);

            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret(SECRET_NAME);

            assertEquals(result, "");
            verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getSecret when SdkClientException is thrown returns empty string")
    public void testGetSecretWithSdkClientException() {
        Properties properties = new Properties();

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                    .thenThrow(SdkClientException.create("AWS SDK Error", new RuntimeException()));

            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret(SECRET_NAME);

            assertEquals(result, "");
            verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getSecret returns null when retrieved secret value is null")
    public void testGetSecretWhenSecretValueIsNull() {
        Properties properties = new Properties();

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            GetSecretValueResponse response = GetSecretValueResponse.builder()
                    .secretString(null)
                    .build();
            when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                    .thenReturn(response);

            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret(SECRET_NAME);

            // The method logs a warning but returns null when secret string is null
            assertNull(result);
            verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test getEncryptedData throws UnsupportedOperationException when encryption is disabled",
            expectedExceptions = UnsupportedOperationException.class)
    public void testGetEncryptedDataWhenEncryptionDisabled() {
        Properties properties = new Properties();

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            awsSecretRepository.init(properties, "testId");
            awsSecretRepository.getEncryptedData(SECRET_NAME);
        }
    }

    @Test(description = "Test parent repository getter and setter")
    public void testParentRepositoryGetterAndSetter() {
        awsSecretRepository.setParent(parentRepository);
        SecretRepository result = awsSecretRepository.getParent();

        assertEquals(result, parentRepository);
    }

    @Test(description = "Test getParent returns null when not set")
    public void testGetParentReturnsNullWhenNotSet() {
        SecretRepository result = awsSecretRepository.getParent();

        assertNull(result);
    }

    @Test(description = "Test getSecret with delimiter at beginning")
    public void testGetSecretWithDelimiterAtBeginning() {
        Properties properties = new Properties();
        String invalidAlias = VERSION_DELIMITER + SECRET_NAME;

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret(invalidAlias);

            assertEquals(result, "");
            verify(secretsManagerClient, never()).getSecretValue(any(GetSecretValueRequest.class));
        }
    }

    @Test(description = "Test init with encryption enabled warning when property not set")
    public void testInitWithEncryptionPropertyNotSet() {
        Properties properties = new Properties();

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn(null);

            awsSecretRepository.init(properties, "testId");

            // Should not throw exception, just log warning
            mockedClient.verify(() -> AWSSecretManagerClient.getInstance(properties), times(1));
        }
    }

    @Test(description = "Test constructor with keystores")
    public void testConstructorWithKeystores() {
        AWSSecretRepository repository = new AWSSecretRepository(null, null);

        assertNotNull(repository);
    }

    @Test(description = "Test default constructor")
    public void testDefaultConstructor() {
        AWSSecretRepository repository = new AWSSecretRepository();

        assertNotNull(repository);
    }

    @Test(description = "Test setParent with null")
    public void testSetParentWithNull() {
        awsSecretRepository.setParent(null);
        assertNull(awsSecretRepository.getParent());
    }

    @Test(description = "Test getSecret with empty string after hash")
    public void testGetSecretWithEmptyStringAfterHash() {
        Properties properties = new Properties();
        String secretAlias = SECRET_NAME + VERSION_DELIMITER;

        try (MockedStatic<AWSSecretManagerClient> mockedClient = mockStatic(AWSSecretManagerClient.class);
             MockedStatic<AWSVaultUtils> mockedUtils = mockStatic(AWSVaultUtils.class)) {

            mockedClient.when(() -> AWSSecretManagerClient.getInstance(properties))
                    .thenReturn(secretsManagerClient);
            mockedUtils.when(() -> AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED))
                    .thenReturn("false");

            GetSecretValueResponse response = GetSecretValueResponse.builder()
                    .secretString(SECRET_VALUE)
                    .build();
            when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                    .thenReturn(response);

            awsSecretRepository.init(properties, "testId");
            String result = awsSecretRepository.getSecret(secretAlias);

            // Should retrieve secret with null version (latest)
            assertEquals(result, SECRET_VALUE);
        }
    }
}
