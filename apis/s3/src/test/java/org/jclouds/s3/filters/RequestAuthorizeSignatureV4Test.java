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
import com.google.common.base.Suppliers;
import com.google.common.collect.ImmutableList;
import com.google.common.net.HttpHeaders;
import com.google.common.net.MediaType;
import com.google.inject.Injector;
import com.google.inject.Module;
import org.jclouds.ContextBuilder;
import org.jclouds.date.DateService;
import org.jclouds.date.TimeStamp;
import org.jclouds.date.internal.SimpleDateFormatDateService;
import org.jclouds.domain.Credentials;
import org.jclouds.http.HttpRequest;
import org.jclouds.io.ContentMetadataBuilder;
import org.jclouds.io.MutableContentMetadata;
import org.jclouds.io.Payload;
import org.jclouds.io.payloads.StringPayload;
import org.jclouds.logging.config.NullLoggingModule;
import org.jclouds.reflect.Invocation;
import org.jclouds.rest.ConfiguresHttpApi;
import org.jclouds.rest.internal.BaseRestApiTest;
import org.jclouds.rest.internal.GeneratedHttpRequest;
import org.jclouds.s3.S3ApiMetadata;
import org.jclouds.s3.S3Client;
import org.jclouds.s3.config.S3HttpApiModule;
import org.jclouds.s3.config.S3ObjectModule;
import org.jclouds.s3.config.S3ParserModule;
import org.jclouds.s3.options.PutBucketOptions;
import org.testng.annotations.Test;

import java.util.Date;

import static org.jclouds.reflect.Reflection2.method;
import static org.testng.Assert.assertEquals;

/**
 * Tests behavior of {@code RequestAuthorizeSignature}
 */
// NOTE:without testName, this will not call @Before* and fail w/NPE during surefire
@Test(groups = "unit", testName = "RequestAuthorizeSignatureV4Test")
public class RequestAuthorizeSignatureV4Test {
    public static final String IDENTITY = "AKIAPAEBI3QI4EXAMPLE";
    public static final String CREDENTIAL = "oHkkcPcOjJnoAXpjT8GXdNeBjo6Ru7QeFExAmPlE";
    public static final String TIMESTAMP = "Thu, 03 Feb 2015 07:11:11 GMT";

    public static final String AWS_SDK_SIGNED_RESULT = "AWS4-HMAC-SHA256 Credential=AKIAPAEBI3QI4EXAMPLE/20150203/cn-north-1/s3/aws4_request, SignedHeaders=content-type;host;user-agent;x-amz-content-sha256;x-amz-date, Signature=5392bd9ec80e9d67efeb65aa96f8360a893d42210d97e34021f06ec570b171d3";

    String bucketName = "test-bucket";

    @ConfiguresHttpApi
    private static final class TestS3HttpApiModule extends S3HttpApiModule<S3Client> {
        @Override
        protected String provideTimeStamp(@TimeStamp Supplier<String> cache) {
            return TIMESTAMP;
        }

        @Override
        protected Date provideTimeStampDate(@TimeStamp Supplier<Date> cache) {
            return new SimpleDateFormatDateService().rfc822DateParse(TIMESTAMP);
        }
    }

    public static Injector injector(Credentials creds) {
        return ContextBuilder.newBuilder(new S3ApiMetadata())
            .credentialsSupplier(Suppliers.<Credentials>ofInstance(creds))
            .modules(ImmutableList.<Module>of(
                    new BaseRestApiTest.MockModule(),
                    new NullLoggingModule(),
                    new TestS3HttpApiModule())
            ).buildInjector();
    }

    public static RequestAuthorizeSignatureV4 filter(Credentials creds) {
        return injector(creds).getInstance(S3RequestAuthorizeSignatureV4.class);
    }

    Credentials temporaryCredentials = new Credentials.Builder()
        .identity(IDENTITY)
        .credential(CREDENTIAL)
        .build();

    Invocation invocation = Invocation.create(method(S3Client.class, "getBucketLocation", String.class), ImmutableList.<Object>of(bucketName));

    HttpRequest getBucketLocation = GeneratedHttpRequest.builder().method("GET")
        .invocation(invocation)
        .endpoint("https://s3.cn-north-1.amazonaws.com.cn/")
        .addHeader(HttpHeaders.HOST, bucketName + ".s3.cn-north-1.amazonaws.com.cn")
        .addHeader(HttpHeaders.USER_AGENT, "aws-sdk-java/1.9.17 Linux/3.14.30-1-lts OpenJDK_64-Bit_Server_VM/24.75-b04/1.7.0_75")
        .build();

    @Test
    void testSignature() {
        StringPayload stringPayload = new StringPayload("");
        stringPayload.getContentMetadata().setContentType("application/x-www-form-urlencoded; charset=utf-8");
        getBucketLocation.setPayload(stringPayload);

        HttpRequest filtered = filter(temporaryCredentials).filter(getBucketLocation);
        assertEquals(filtered.getFirstHeaderOrNull("Authorization"), AWS_SDK_SIGNED_RESULT);
    }
}
