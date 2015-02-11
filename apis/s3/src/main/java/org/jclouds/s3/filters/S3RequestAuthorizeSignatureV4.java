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


import com.google.common.base.Supplier;
import com.google.inject.Inject;
import org.jclouds.crypto.Crypto;
import org.jclouds.date.TimeStamp;
import org.jclouds.domain.Credentials;
import org.jclouds.http.HttpRequest;
import org.jclouds.http.internal.SignatureWire;
import org.jclouds.io.Payload;
import org.jclouds.location.Provider;

import javax.inject.Named;
import java.net.URI;
import java.util.Date;

import static org.jclouds.aws.reference.AWSConstants.PROPERTY_HEADER_TAG;
import static org.jclouds.s3.reference.S3Constants.PROPERTY_S3_VIRTUAL_HOST_BUCKETS;

/**
 * AWS S3 request signature v4
 * @author ZhaoJin
 *
 */
public class S3RequestAuthorizeSignatureV4 extends RequestAuthorizeSignatureV4 {
    @Inject
    public S3RequestAuthorizeSignatureV4(
        SignatureWire signatureWire,
        @Named(PROPERTY_S3_VIRTUAL_HOST_BUCKETS) boolean isVhostStyle,
        @Named(PROPERTY_HEADER_TAG) String headerTag,
        @Provider Supplier<Credentials> creds,
        @TimeStamp javax.inject.Provider<Date> timestampProvider,
        ServiceAndRegion serviceAndRegion,
        Crypto crypto) {
        super(signatureWire, isVhostStyle, headerTag, creds, timestampProvider, serviceAndRegion, crypto);
    }

    // S3 Service required content hash
    @Override
    protected String calculateContentHash(
        HttpRequest.Builder requestBuilder,
        String method,
        URI endpoint,
        Payload payload
    ) {
        // To be consistent with other service clients using sig-v4,
        // we just set the header as "required", and AWS4Signer.sign() will be
        // notified to pick up the header value returned by this method.
        requestBuilder.replaceHeader("x-amz-content-sha256", "required");
        return super.calculateContentHash(requestBuilder, method, endpoint, payload);

    }
}
