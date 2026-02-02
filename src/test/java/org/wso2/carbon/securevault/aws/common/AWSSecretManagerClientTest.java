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
import org.wso2.carbon.securevault.aws.exception.AWSVaultRuntimeException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Properties;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.AWS_REGION;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.CLI;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.CREDENTIAL_PROVIDERS;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.EC2;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ECS;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ENV;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.K8S_SERVICE_ACCOUNT;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.SECRET_REPOSITORIES;

/**
 * Unit test class for AWSSecretManagerClient.
 * Note: This class uses singleton pattern and cannot be easily mocked with Mockito.
 * Tests focus on validation logic and error handling.
 */
public class AWSSecretManagerClientTest {

    @BeforeMethod
    public void setUp() {
        resetSecretsClient();
    }

    @AfterMethod
    public void tearDown() {
        resetSecretsClient();
    }

    /**
     * Reset the static secretsClient field to ensure test isolation.
     */
    private void resetSecretsClient() {
        try {
            Field field = AWSSecretManagerClient.class.getDeclaredField("secretsClient");
            field.setAccessible(true);
            synchronized (AWSSecretManagerClient.class) {
                field.set(null, null);
            }
        } catch (Exception e) {
            // Fail silently - field reset is for test isolation
        }
        
        // Also reset the propertiesPrefix in AWSVaultUtils
        try {
            Field prefixField = AWSVaultUtils.class.getDeclaredField("propertiesPrefix");
            prefixField.setAccessible(true);
            synchronized (AWSVaultUtils.class) {
                prefixField.set(null, null);
            }
        } catch (Exception e) {
            // Fail silently - field reset is for test isolation
        }
    }

    @Test(description = "Test getInstance throws exception for invalid regions",
            dataProvider = "invalidRegions",
            expectedExceptions = AWSVaultRuntimeException.class)
    public void testGetInstanceWithInvalidRegions(String region, String expectedMessagePattern, String description) {
        Properties properties = new Properties();
        properties.setProperty(SECRET_REPOSITORIES, "vault");
        
        if (region != null) {
            properties.setProperty("secretRepositories.vault.properties." + AWS_REGION, region);
        }
        
        if ("invalid-region-12345".equals(region)) {
            properties.setProperty("secretRepositories.vault.properties." + CREDENTIAL_PROVIDERS, ENV);
        }

        try {
            AWSSecretManagerClient.getInstance(properties);
        } catch (AWSVaultRuntimeException e) {
            assertTrue(e.getMessage().matches(expectedMessagePattern),
                    "Exception message should match pattern for " + description);
            throw e;
        }
    }

    @Test(description = "Test getInstance with valid configurations",
          dataProvider = "validClientConfigs")
    public void testGetInstanceWithValidConfigs(String region, String credentialProvider,
                                                String configPrefix, String description) {
        resetSecretsClient();

        Properties properties = new Properties();
        if ("secretProviders".equals(configPrefix)) {
            properties.setProperty("secretProviders", "vault");
            properties.setProperty("secretProviders.vault.repositories.aws.properties." + AWS_REGION, region);
            properties.setProperty("secretProviders.vault.repositories.aws.properties."
                    + CREDENTIAL_PROVIDERS, credentialProvider);
        } else {
            properties.setProperty(SECRET_REPOSITORIES, "vault");
            properties.setProperty("secretRepositories.vault.properties." + AWS_REGION, region);
            properties.setProperty("secretRepositories.vault.properties."
                    + CREDENTIAL_PROVIDERS, credentialProvider);
        }

        SecretsManagerClient client = (SecretsManagerClient) AWSSecretManagerClient.getInstance(properties);
        assertNotNull(client, "SecretsManagerClient should be created for " + description);
    }

    @Test(description = "Test getInstance returns singleton instance")
    public void testGetInstanceSingleton() {
        resetSecretsClient();

        Properties properties = new Properties();
        properties.setProperty(SECRET_REPOSITORIES, "vault");
        properties.setProperty("secretRepositories.vault.properties." + AWS_REGION, "us-west-2");
        properties.setProperty("secretRepositories.vault.properties." + CREDENTIAL_PROVIDERS, ENV);

        SecretsManagerClient client1 = (SecretsManagerClient) AWSSecretManagerClient.getInstance(properties);
        SecretsManagerClient client2 = (SecretsManagerClient) AWSSecretManagerClient.getInstance(properties);

        assertSame(client1, client2, "getInstance should return the same instance (singleton)");
    }

    /**
     * DataProvider for credential provider tests.
     */
    @DataProvider(name = "credentialProviders")
    public Object[][] credentialProvidersData() {
        return new Object[][] {
            { ENV, "us-west-2" },
            { EC2, "eu-west-1" },
            { ECS, "ap-south-1" },
            { CLI, "us-east-2" },
            { K8S_SERVICE_ACCOUNT, "ca-central-1" }
        };
    }

    /**
     * DataProvider for invalid region tests.
     */
    @DataProvider(name = "invalidRegions")
    public Object[][] invalidRegionsData() {
        return new Object[][] {
            { "", ".*AWS Region has not been specified.*", "empty region" },
            { null, ".*AWS Region has not been specified.*", "null region" },
            { "invalid-region-12345", ".*AWS Region specified is invalid.*", "invalid region format" }
        };
    }

    /**
     * DataProvider for credential provider edge cases.
     */
    @DataProvider(name = "credentialProviderEdgeCases")
    public Object[][] credentialProviderEdgeCasesData() {
        return new Object[][] {
            { "", "ap-southeast-1", "empty credential provider" },
            { "INVALID_TYPE", "ap-northeast-1", "invalid credential provider" },
            { " " + ENV + " , " + EC2 + " , " + CLI + " ", "sa-east-1", "whitespace in credential providers" }
        };
    }

    /**
     * DataProvider for valid client creation tests.
     */
    @DataProvider(name = "validClientConfigs")
    public Object[][] validClientConfigsData() {
        return new Object[][] {
            { "us-east-1", ENV, "secretRepositories", "standard config" },
            { "us-west-1", ENV, "secretProviders", "novel config" },
            { "eu-central-1", ENV + "," + EC2 + "," + ECS + "," + CLI, "secretRepositories", "multiple credentials" }
        };
    }

    @Test(description = "Test getInstance with different credential providers",
          dataProvider = "credentialProviders")
    public void testGetInstanceWithCredentialProviders(String credentialProvider, String region) {
        resetSecretsClient();

        Properties properties = new Properties();
        properties.setProperty(SECRET_REPOSITORIES, "vault");
        properties.setProperty("secretRepositories.vault.properties." + AWS_REGION, region);
        properties.setProperty("secretRepositories.vault.properties." + CREDENTIAL_PROVIDERS, credentialProvider);

        SecretsManagerClient client = (SecretsManagerClient) AWSSecretManagerClient.getInstance(properties);

        assertNotNull(client, "SecretsManagerClient should be created for " + credentialProvider);
    }

    @Test(description = "Test getInstance with credential provider edge cases",
          dataProvider = "credentialProviderEdgeCases")
    public void testGetInstanceWithCredentialProviderEdgeCases(String credentialProvider,
                                                               String region,
                                                               String description) {
        resetSecretsClient();

        Properties properties = new Properties();
        properties.setProperty(SECRET_REPOSITORIES, "vault");
        properties.setProperty("secretRepositories.vault.properties." + AWS_REGION, region);
        properties.setProperty("secretRepositories.vault.properties." + CREDENTIAL_PROVIDERS, credentialProvider);

        SecretsManagerClient client = (SecretsManagerClient) AWSSecretManagerClient.getInstance(properties);

        assertNotNull(client, "SecretsManagerClient should be created for " + description);
    }

    @Test(description = "Test AWS SDK integration components")
    public void testAWSSDKIntegration() throws Exception {
        resetSecretsClient();

        Properties properties = new Properties();
        properties.setProperty(SECRET_REPOSITORIES, "vault");
        properties.setProperty("secretRepositories.vault.properties." + AWS_REGION, "us-east-1");
        properties.setProperty("secretRepositories.vault.properties." + CREDENTIAL_PROVIDERS,
                ENV + "," + EC2 + "," + CLI);

        // Test client creation and type
        SecretsManagerClient client = (SecretsManagerClient) AWSSecretManagerClient.getInstance(properties);
        assertNotNull(client);
        assertTrue(client.serviceName().toLowerCase().contains("secret"),
                "Client should be a Secrets Manager client");
        assertTrue(client.getClass().getName().contains("SecretsManager"),
                "Should be a SecretsManagerClient implementation");

        // Test ApacheHttpClient availability
        SdkHttpClient httpClient = ApacheHttpClient.create();
        assertNotNull(httpClient, "ApacheHttpClient should be available");
        httpClient.close();

        // Test SecretsManagerClientBuilder availability
        SecretsManagerClientBuilder builder = SecretsManagerClient.builder();
        assertNotNull(builder, "SecretsManagerClientBuilder should be available");

        // Test credential provider chain creation via reflection
        Method getCredentialProviderMethod = AWSSecretManagerClient.class
                .getDeclaredMethod("getCredentialProviderChain", Properties.class);
        getCredentialProviderMethod.setAccessible(true);
        AwsCredentialsProvider credentialsProvider =
                (AwsCredentialsProvider) getCredentialProviderMethod.invoke(null, properties);
        assertNotNull(credentialsProvider, "Credentials provider should be created");
        assertTrue(credentialsProvider.toString().contains("AwsCredentialsProviderChain"),
                "Should create a credentials provider chain");

        // Test getAWSRegion method via reflection
        Method getAWSRegionMethod = AWSSecretManagerClient.class
                .getDeclaredMethod("getAWSRegion", Properties.class);
        getAWSRegionMethod.setAccessible(true);
        Region region = (Region) getAWSRegionMethod.invoke(null, properties);
        assertNotNull(region, "Region should not be null");
        assertTrue(region instanceof Region, "Should return Region type");

        // Test AWS regions are valid
        assertTrue(Region.regions().contains(Region.US_EAST_1));
        assertTrue(Region.regions().contains(Region.EU_WEST_1));
        assertTrue(Region.regions().contains(Region.AP_SOUTH_1));
    }
}
