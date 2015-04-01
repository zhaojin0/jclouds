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

import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedMap;
import com.google.common.net.HttpHeaders;
import com.google.inject.Inject;
import org.jclouds.aws.domain.SessionCredentials;
import org.jclouds.crypto.Crypto;
import org.jclouds.date.TimeStamp;
import org.jclouds.domain.Credentials;
import org.jclouds.http.HttpException;
import org.jclouds.http.HttpRequest;
import org.jclouds.http.internal.SignatureWire;
import org.jclouds.location.Provider;

import javax.inject.Named;
import java.util.Date;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.io.BaseEncoding.base16;
import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static com.google.common.net.HttpHeaders.DATE;
import static com.google.common.net.HttpHeaders.HOST;
import static org.jclouds.aws.reference.AWSConstants.PROPERTY_HEADER_TAG;
import static org.jclouds.s3.filters.AwsSignatureV4Constants.AMZ_ALGORITHM_HMAC_SHA256;
import static org.jclouds.s3.filters.AwsSignatureV4Constants.AMZ_CONTENT_SHA256_HEADER;
import static org.jclouds.s3.filters.AwsSignatureV4Constants.AMZ_DATE_HEADER;
import static org.jclouds.s3.filters.AwsSignatureV4Constants.AMZ_DECODED_CONTENT_LENGTH_HEADER;
import static org.jclouds.s3.filters.AwsSignatureV4Constants.AMZ_SECURITY_TOKEN_HEADER;
import static org.jclouds.s3.filters.AwsSignatureV4Constants.CONTENT_ENCODING_HEADER_AWS_CHUNKED;
import static org.jclouds.s3.filters.AwsSignatureV4Constants.STREAMING_BODY_SHA256;
import static org.jclouds.s3.reference.S3Constants.PROPERTY_S3_VIRTUAL_HOST_BUCKETS;

/**
 * AWS4 signer sign 'chunked' uploads.
 */
public class Aws4SignerForChunkedUpload extends Aws4SignerBase {
    @Inject
    public Aws4SignerForChunkedUpload(SignatureWire signatureWire,
            @Named(PROPERTY_S3_VIRTUAL_HOST_BUCKETS) boolean isVhostStyle,
            @Named(PROPERTY_HEADER_TAG) String headerTag,
            @Provider Supplier<Credentials> creds, @TimeStamp Supplier<Date> timestampProvider,
            ServiceAndRegion serviceAndRegion, Crypto crypto) {
        super(signatureWire, headerTag, creds, timestampProvider, serviceAndRegion, crypto);
    }

    protected HttpRequest sign(HttpRequest request) throws HttpException {
        checkArgument(request.getHeaders().containsKey(HOST), "request is not ready to sign; host not present");

        String host = request.getFirstHeaderOrNull(HOST);

        Date date = timestampProvider.get();
        String timestamp = timestampFormat.format(date);
        String datestamp = dateFormat.format(date);

        String service = serviceAndRegion.service();
        String region = serviceAndRegion.region(host);
        String credentialScope = Joiner.on('/').join(datestamp, region, service, "aws4_request");

        HttpRequest.Builder<?> requestBuilder = request.toBuilder() //
                .removeHeader(AUTHORIZATION) // remove Authorization
                .removeHeader(DATE); // remove date

        ImmutableMap.Builder<String, String> signedHeadersBuilder = ImmutableSortedMap.<String, String>naturalOrder();



        // content-encoding
        requestBuilder.replaceHeader(HttpHeaders.CONTENT_ENCODING, CONTENT_ENCODING_HEADER_AWS_CHUNKED);
        signedHeadersBuilder.put(HttpHeaders.CONTENT_ENCODING, CONTENT_ENCODING_HEADER_AWS_CHUNKED);


        // x-amz-decoded-content-length
        requestBuilder.replaceHeader(AMZ_DECODED_CONTENT_LENGTH_HEADER,
                String.valueOf(request.getPayload().getContentMetadata().getContentLength()));

        // Content Type
        // content-type is not a required signing param. However, examples use this, so we include it to ease testing.
        String contentType = getContentType(request);
        if (!Strings.isNullOrEmpty(contentType)) {
            requestBuilder.replaceHeader(HttpHeaders.CONTENT_TYPE, contentType);
            signedHeadersBuilder.put(HttpHeaders.CONTENT_TYPE.toLowerCase(), contentType);
        } else {
            requestBuilder.removeHeader(HttpHeaders.CONTENT_TYPE);
        }

        // host
        signedHeadersBuilder.put(HttpHeaders.HOST.toLowerCase(), host);

        // user-agent
        if (request.getHeaders().containsKey(HttpHeaders.USER_AGENT)) {
            signedHeadersBuilder.put(HttpHeaders.USER_AGENT.toLowerCase(),
                    request.getFirstHeaderOrNull(HttpHeaders.USER_AGENT));
        }

        // all x-amz-* headers
        appendAmzHeaders(request, signedHeadersBuilder);

        // x-amz-security-token
        Credentials credentials = creds.get();
        if (credentials instanceof SessionCredentials) {
            String token = SessionCredentials.class.cast(credentials).getSessionToken();
            requestBuilder.replaceHeader(AMZ_SECURITY_TOKEN_HEADER, token);
            signedHeadersBuilder.put(AMZ_SECURITY_TOKEN_HEADER.toLowerCase(), token);
        }

        // x-amz-content-sha256
        String contentSha256 = getPayloadHash();
        requestBuilder.replaceHeader(AMZ_CONTENT_SHA256_HEADER, contentSha256);
        signedHeadersBuilder.put(AMZ_CONTENT_SHA256_HEADER.toLowerCase(), contentSha256);

        // put x-amz-date
        requestBuilder.replaceHeader(AMZ_DATE_HEADER, timestamp);
        signedHeadersBuilder.put(AMZ_DATE_HEADER.toLowerCase(), timestamp);

        ImmutableMap<String, String> signedHeaders = signedHeadersBuilder.build();

        String stringToSign = createStringToSign(request.getMethod(), request.getEndpoint(), signedHeaders, timestamp,
                credentialScope, contentSha256);
        signatureWire.getWireLog().debug("<< " + stringToSign);

        byte[] signatureKey = signatureKey(credentials.credential, datestamp, region, service);
        String signature = base16().lowerCase().encode(hmacSHA256(stringToSign, signatureKey));

        StringBuilder authorization = new StringBuilder(AMZ_ALGORITHM_HMAC_SHA256).append(" ");
        authorization.append("Credential=").append(Joiner.on("/").join(credentials.identity, credentialScope))
                .append(", ");
        authorization.append("SignedHeaders=").append(Joiner.on(";").join(signedHeaders.keySet()))
                .append(", ");
        authorization.append("Signature=").append(signature);
        return request.toBuilder().replaceHeader(HttpHeaders.AUTHORIZATION, authorization.toString()).build();

    }

    protected String getPayloadHash() {
        return STREAMING_BODY_SHA256;
    }
}
