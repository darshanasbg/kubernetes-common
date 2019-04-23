/*
* Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package org.wso2.carbon.membership.scheme.kubernetes.api;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.membership.scheme.kubernetes.Constants;
import org.wso2.carbon.utils.xml.StringUtils;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public class KubernetesHttpsApiEndpoint extends KubernetesApiEndpoint {

    private static final Log log = LogFactory.getLog(KubernetesHttpsApiEndpoint.class);

    public KubernetesHttpsApiEndpoint(URL url, boolean skipMasterSSLVerification) {
        super(url);
        if (skipMasterSSLVerification) {
            disableCertificateValidation();
        }
    }

    @Override
    public void createConnection() throws IOException {
        log.debug("Connecting to Kubernetes API server...");
        connection = (HttpsURLConnection) url.openConnection();
        String bearerToken = getServiceAccountToken();
        if (StringUtils.isEmpty(bearerToken)) {
            bearerToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9" +
                    ".eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJ3c28yaXMiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoiZGVmYXVsdC10b2tlbi03YmptNiIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiYjlhNjhkZmEtNjVkMy0xMWU5LTkxZWMtMDYyNWQyYTY5NjI0Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OndzbzJpczpkZWZhdWx0In0.iByjJDrH2cUzJBgcZmEzQnO4pzUch6cfuIVzpTJO6XWXf-tuPbPA0LHWYTBEk1YIK3LSraBLjZnZBEiRa65ybBLRbtqVUiJQypGVwRootlA3wbYpqRMLEs4I65f4KM1SrJ7nSxKCh4YvBI3F46E_oNhaLnFJgP1BpMt-M6yH5pi0qg5Mbml9M8nY8TjCQ4oj4fZNQ9N8bQgUydP1xat-uVGo10IK6Fnq1BcLekXXPljUaPeldmZhwC6HmZAiqFJYPyv59xeblqM3XeCwys4S8xvOMWNNar3lVAWzfFP0jVX0F2T-1DY-OvuMLYt4zkzfcFqFTQJvq1xdj0kFpzKvDw\u2029";
        }

        log.info("H*********-84: Bearer Token: " + bearerToken);
        connection.addRequestProperty(Constants.AUTHORIZATION_HEADER, "Bearer " + bearerToken);
        log.debug("Connected successfully");
    }

    @Override
    public void createConnection(String username, String password) throws IOException {
        log.debug("Connecting to Kubernetes API server with basic auth...");
        connection = (HttpsURLConnection) url.openConnection();
        createBasicAuthenticationHeader(username, password);
        log.debug("Connected successfully");
    }


    @Override
    public void disconnect() {
        log.debug("Disconnecting from Kubernetes API server...");
        connection.disconnect();
        log.debug("Disconnected successfully");
    }

    private static void disableCertificateValidation() {

        TrustManager[] dummyTrustMgr = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // do nothing
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // do nothing
                    }
                }};

        // Ignore differences between given hostname and certificate hostname
        HostnameVerifier dummyHostVerifier = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                // always true
                return true;
            }
        };

        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, dummyTrustMgr, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(dummyHostVerifier);
        } catch (NoSuchAlgorithmException | KeyManagementException ignored) {
        }
    }

    private String getServiceAccountToken() throws IOException {
        String bearerTokenFileLocation = System.getenv("BEARER_TOKEN_FILE_LOCATION");
        if (StringUtils.isEmpty(bearerTokenFileLocation)) {
            bearerTokenFileLocation = Constants.BEARER_TOKEN_FILE_LOCATION;
        }
        return new String(Files.readAllBytes(Paths.get(bearerTokenFileLocation)), StandardCharsets.UTF_8);
    }
}
