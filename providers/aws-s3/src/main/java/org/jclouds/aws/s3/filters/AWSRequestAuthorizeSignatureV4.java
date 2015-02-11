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
package org.jclouds.aws.s3.filters;

import com.google.common.base.Supplier;
import org.jclouds.crypto.Crypto;
import org.jclouds.date.TimeStamp;
import org.jclouds.domain.Credentials;
import org.jclouds.http.internal.SignatureWire;
import org.jclouds.s3.filters.S3RequestAuthorizeSignatureV4;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import java.util.Date;

import static org.jclouds.aws.reference.AWSConstants.PROPERTY_HEADER_TAG;
import static org.jclouds.s3.reference.S3Constants.PROPERTY_S3_VIRTUAL_HOST_BUCKETS;

/**
 * Signs the AWS S3 request, supporting temporary signatures.
 */
@Singleton
public class AWSRequestAuthorizeSignatureV4 extends S3RequestAuthorizeSignatureV4 {

    @Inject
    public AWSRequestAuthorizeSignatureV4(
        SignatureWire signatureWire,
        @Named(PROPERTY_S3_VIRTUAL_HOST_BUCKETS) boolean isVhostStyle,
        @Named(PROPERTY_HEADER_TAG) String headerTag,
        @org.jclouds.location.Provider Supplier<Credentials> creds,
        @TimeStamp Provider<Date> timestampProvider,
        ServiceAndRegion serviceAndRegion,
        Crypto crypto
    ) {
        super(signatureWire,
            isVhostStyle,
            headerTag,
            creds,
            timestampProvider,
            serviceAndRegion, crypto);
    }
}
