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
package org.jclouds.aws.s3.blobstore;

import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableSet;
import com.google.inject.Module;
import com.google.inject.Scopes;
import org.jclouds.aws.s3.AWSS3ApiMetadata;
import org.jclouds.aws.s3.AWSS3ProviderMetadata;
import org.jclouds.aws.s3.blobstore.config.AWSS3BlobStoreContextModule;
import org.jclouds.aws.s3.config.AWSS3HttpApiModule;
import org.jclouds.aws.s3.filters.AWSRequestAuthorizeSignatureV4;
import org.jclouds.blobstore.BlobRequestSigner;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.date.TimeStamp;
import org.jclouds.date.internal.SimpleDateFormatDateService;
import org.jclouds.http.HttpRequest;
import org.jclouds.providers.ProviderMetadata;
import org.jclouds.rest.ConfiguresHttpApi;
import org.jclouds.s3.blobstore.S3BlobSignerExpectTest;
import org.jclouds.s3.filters.RequestAuthorizeSignature;
import org.testng.SkipException;
import org.testng.annotations.Test;

import java.util.Date;
import java.util.Properties;

import static org.jclouds.Constants.*;
import static org.testng.Assert.assertEquals;

@Test(groups = "unit", testName = "AWSS3BlobSignerV4ExpectTest")
public class AWSS3BlobSignerV4ExpectTest extends S3BlobSignerExpectTest {
    private static final String IDENTITY ="AKIAIOSFODNN7EXAMPLE";
    private static final String CREDENTIAL= "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String DATE = "Fri, 20 Feb 2015 08:42:44 GMT";

    public AWSS3BlobSignerV4ExpectTest() {
        provider = null;
    }

    @Override
    protected HttpRequest getBlobWithTime() {
        return HttpRequest.builder().method("GET")
            .endpoint("https://examplebucket.s3.amazonaws.com/test.txt" +
                "?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20150220/us-east-1/s3/aws4_request" +
                "&X-Amz-Date=20150220T084244Z" +
                "&X-Amz-Expires=86400" +
                "&X-Amz-SignedHeaders=host" +
                "&X-Amz-Signature=d5f572953fdba30c3ab217a36be0ec6061afd0be020ff3aa1f5da8cae8c584d3")
            .addHeader("Host", "examplebucket.s3.amazonaws.com")
            .addHeader("Content-Type", "application/x-www-form-urlencoded")
            .build();
    }

    @Test
    @Override
    public void testSignGetBlobWithTime() {
        BlobStore getBlobWithTime = requestsSendResponses(init());
        HttpRequest compare = getBlobWithTime();
        HttpRequest signedRequest = getBlobWithTime.getContext().getSigner().signGetBlob("examplebucket", "test.txt", 86400l /* seconds */);
        assertEquals(signedRequest, compare);
    }

    protected HttpRequest _putBlobWithTime() {
        return HttpRequest.builder().method("PUT")
            .endpoint("https://examplebucket.s3.amazonaws.com/test.txt" +
                "?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20150220/us-east-1/s3/aws4_request" +
                "&X-Amz-Date=20150220T084244Z" +
                "&X-Amz-Expires=86400" +
                "&X-Amz-SignedHeaders=host" +
                "&X-Amz-Signature=29e9db3b175db6c83e974fd812687e6f09db51a259bfcbab39654daf0021c802")
            .addHeader("Expect", "100-continue")
            .addHeader("Host", "examplebucket.s3.amazonaws.com")
            .addHeader("Content-Type", "text/plain")
            .build();
    }

    @Test
    @Override
    public void testSignPutBlobWithTime() throws Exception {
        BlobStore signPutBloblWithTime = requestsSendResponses(init());
        Blob blob = signPutBloblWithTime.blobBuilder("test.txt").payload(text).contentType("text/plain").build();
        HttpRequest compare = _putBlobWithTime();
        compare.setPayload(blob.getPayload());
        HttpRequest signedRequest = signPutBloblWithTime.getContext().getSigner().signPutBlob("examplebucket", blob, 86400l /* seconds */);
        assertEquals(signedRequest, compare);
    }

    @Override
    protected HttpRequest putBlob() {
        return HttpRequest.builder().method("PUT")
            .endpoint("https://examplebucket.s3.amazonaws.com/test.txt")
            .addHeader("Expect", "100-continue")
            .addHeader("Date", "Thu, 05 Jun 2008 16:38:19 GMT")
            .addHeader("Authorization", "AWS identity:j9Dy/lmmvlCKjA4lkqZenLxMkR4=").build();
    }

    @Override
    public void testSignPutBlob() {
        throw new SkipException("skip testSignPutBlob");
    }

    @Override
    public void testSignGetBlob() {
        throw new SkipException("skip testSignGetBlob");
    }

    @Override
    public void testSignGetBlobWithOptions() {
        throw new SkipException("skip testSignGetBlobWithOptions");
    }

    @Override
    public void testSignRemoveBlob() {
        throw new SkipException("skip testSignRemoveBlob");
    }

    @Override
    protected Module createModule() {
        return new TestAWSS3SignerV4HttpApiModule();
    }

    @Override
    protected Properties setupProperties() {
        Properties props = super.setupProperties();
        props.put(PROPERTY_IDENTITY, IDENTITY);
        props.put(PROPERTY_CREDENTIAL, CREDENTIAL);
        return props;
    }

    @Override
    protected ProviderMetadata createProviderMetadata() {
        AWSS3ApiMetadata.Builder apiBuilder = new AWSS3ApiMetadata().toBuilder();
        apiBuilder.defaultModules(ImmutableSet.<Class<? extends Module>>of(TestAWSS3SignerV4HttpApiModule.class, TestAWSS3BlobStoreContextModule.class));
        return new AWSS3ProviderMetadata().toBuilder().apiMetadata(apiBuilder.build()).build();
    }

    public static final class TestAWSS3BlobStoreContextModule extends AWSS3BlobStoreContextModule {

        @Override
        protected void bindRequestSigner() {
            // replace AWSS3BlobRequestSigner aws s3 with AWSS3BlobRequestSignerV4
            bind(BlobRequestSigner.class).to(AWSS3BlobRequestSignerV4.class);
        }

    }

    @ConfiguresHttpApi
    public static final class TestAWSS3SignerV4HttpApiModule extends AWSS3HttpApiModule {
        @Override
        protected void configure() {
            super.configure();
        }

        @Override
        protected void bindRequestSigner() {
            bind(RequestAuthorizeSignature.class).to(AWSRequestAuthorizeSignatureV4.class).in(Scopes.SINGLETON);
        }

        @Override
        @TimeStamp
        protected String provideTimeStamp(@TimeStamp Supplier<String> cache) {
            return DATE;
        }

        @Override
        @TimeStamp
        protected Date provideTimeStampDate(@TimeStamp Supplier<Date> cache) {
            return new SimpleDateFormatDateService().rfc822DateParse(DATE);
        }
    }
}
