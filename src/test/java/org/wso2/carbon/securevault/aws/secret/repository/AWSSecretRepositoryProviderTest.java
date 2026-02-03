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
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;

/**
 * Unit test class for AWSSecretRepositoryProvider with full coverage.
 */
public class AWSSecretRepositoryProviderTest {

    @Mock
    private IdentityKeyStoreWrapper identityKeyStoreWrapper;

    @Mock
    private TrustKeyStoreWrapper trustKeyStoreWrapper;

    private AWSSecretRepositoryProvider provider;
    private AutoCloseable mocks;

    @BeforeMethod
    public void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        provider = new AWSSecretRepositoryProvider();
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test(description = "Test getSecretRepository returns AWSSecretRepository instance")
    public void testGetSecretRepository() {
        SecretRepository repository = provider.getSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);

        Assert.assertNotNull(repository);
        Assert.assertTrue(repository instanceof AWSSecretRepository);
    }

    @Test(description = "Test getSecretRepository with null identity keystore wrapper")
    public void testGetSecretRepositoryWithNullIdentityKeystore() {
        SecretRepository repository = provider.getSecretRepository(null, trustKeyStoreWrapper);

        Assert.assertNotNull(repository);
        Assert.assertTrue(repository instanceof AWSSecretRepository);
    }

    @Test(description = "Test getSecretRepository with null trust keystore wrapper")
    public void testGetSecretRepositoryWithNullTrustKeystore() {
        SecretRepository repository = provider.getSecretRepository(identityKeyStoreWrapper, null);

        Assert.assertNotNull(repository);
        Assert.assertTrue(repository instanceof AWSSecretRepository);
    }

    @Test(description = "Test getSecretRepository with both keystores null")
    public void testGetSecretRepositoryWithBothKeystoresNull() {
        SecretRepository repository = provider.getSecretRepository(null, null);

        Assert.assertNotNull(repository);
        Assert.assertTrue(repository instanceof AWSSecretRepository);
    }

    @Test(description = "Test multiple calls to getSecretRepository return different instances")
    public void testGetSecretRepositoryReturnsNewInstances() {
        SecretRepository repository1 = provider.getSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
        SecretRepository repository2 = provider.getSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);

        Assert.assertNotNull(repository1);
        Assert.assertNotNull(repository2);
        Assert.assertNotSame(repository1, repository2, "Each call should return a new instance");
    }

    @Test(description = "Test provider implements SecretRepositoryProvider interface")
    public void testImplementsInterface() {
        Assert.assertEquals(AWSSecretRepositoryProvider.class.getInterfaces()[0].getName(),
                "org.wso2.securevault.secret.SecretRepositoryProvider");
    }

    @Test(description = "Test provider can be instantiated")
    public void testProviderInstantiation() {
        AWSSecretRepositoryProvider newProvider = new AWSSecretRepositoryProvider();

        Assert.assertNotNull(newProvider);
    }

    @Test(description = "Test multiple providers are independent")
    public void testMultipleProvidersIndependent() {
        AWSSecretRepositoryProvider provider1 = new AWSSecretRepositoryProvider();
        AWSSecretRepositoryProvider provider2 = new AWSSecretRepositoryProvider();

        Assert.assertNotSame(provider1, provider2);

        SecretRepository repo1 = provider1.getSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
        SecretRepository repo2 = provider2.getSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);

        Assert.assertNotSame(repo1, repo2);
    }
}
