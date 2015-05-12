/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jclouds.s3.filters;

import com.google.inject.Singleton;
import org.jclouds.http.HttpException;
import org.jclouds.http.HttpRequest;
import org.jclouds.io.Payload;

import javax.inject.Inject;
import java.util.Locale;

@Singleton
public class RequestAuthorizeSignatureV4 implements RequestAuthorizeSignature {


    private final Aws4SignerForAuthorizationHeader signerForAuthorizationHeader;
    private final Aws4SignerForChunkedUpload signerForChunkedUpload;
    private final Aws4SignerForQueryString signerForQueryString;

    @Inject
    public RequestAuthorizeSignatureV4(Aws4SignerForAuthorizationHeader signerForAuthorizationHeader,
            Aws4SignerForChunkedUpload signerForChunkedUpload,
            Aws4SignerForQueryString signerForQueryString) {
        this.signerForAuthorizationHeader = signerForAuthorizationHeader;
        this.signerForChunkedUpload = signerForChunkedUpload;
        this.signerForQueryString = signerForQueryString;
    }

    @Override
    public HttpRequest filter(HttpRequest request) throws HttpException {
        Payload payload = request.getPayload();
        String method = request.getMethod();
        // only HTTP PUT method, payload not null and cannot repeatable
        if ("PUT".equals(method)
                && payload != null && payload.getContentMetadata().getContentLength() > 0 && !payload.isRepeatable()) {
            return signForChunkedUpload(request);
        }
        return signForAuthorizationHeader(request);
    }

    protected HttpRequest signForAuthorizationHeader(HttpRequest request) {
        return signerForAuthorizationHeader.sign(request);
    }

    protected HttpRequest signForChunkedUpload(HttpRequest request) {
        return signerForChunkedUpload.sign(request);
    }

    // Authenticating Requests by Using Query Parameters (AWS Signature Version 4)

    /**
     * Using query parameters to authenticate requests is useful when you want to express a request entirely in a URL.
     * This method is also referred as presigning a URL. Presigned URLs enable you to grant temporary access to your
     * Amazon S3 resources. The end user can then enter the presigned URL in his or her browser to access the specific
     * Amazon S3 resource. You can also use presigned URLs to embed clickable links in HTML.
     * <p/>
     * For example, you might store videos in an Amazon S3 bucket and make them available on your website by using presigned URLs.
     * Identifies the version of AWS Signature and the algorithm that you used to calculate the signature.
     */
    public HttpRequest signForTemporaryAccess(HttpRequest request, long timeInSeconds) {
        return signerForQueryString.sign(request, timeInSeconds);
    }


}
