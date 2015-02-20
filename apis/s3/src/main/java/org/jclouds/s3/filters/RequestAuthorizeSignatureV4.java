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
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedMap;
import com.google.common.collect.Multimap;
import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteProcessor;
import com.google.common.net.HttpHeaders;
import com.google.common.net.MediaType;
import com.google.common.net.UrlEscapers;
import com.google.inject.ImplementedBy;
import org.jclouds.aws.domain.SessionCredentials;
import org.jclouds.crypto.Crypto;
import org.jclouds.date.TimeStamp;
import org.jclouds.domain.Credentials;
import org.jclouds.http.HttpException;
import org.jclouds.http.HttpRequest;
import org.jclouds.http.Uris;
import org.jclouds.http.internal.SignatureWire;
import org.jclouds.io.Payload;
import org.jclouds.location.Provider;
import org.jclouds.providers.ProviderMetadata;

import javax.inject.Inject;
import javax.inject.Named;
import javax.xml.ws.http.HTTPException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.InvalidKeyException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.base.Charsets.UTF_8;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.io.BaseEncoding.base16;
import static com.google.common.io.ByteStreams.readBytes;
import static com.google.common.net.HttpHeaders.*;
import static org.jclouds.aws.reference.AWSConstants.PROPERTY_HEADER_TAG;
import static org.jclouds.crypto.Macs.asByteProcessor;
import static org.jclouds.http.utils.Queries.queryParser;
import static org.jclouds.s3.filters.AwsSignatureV4Constants.*;
import static org.jclouds.s3.reference.S3Constants.PROPERTY_S3_VIRTUAL_HOST_BUCKETS;
import static org.jclouds.util.Strings2.toInputStream;

public class RequestAuthorizeSignatureV4 implements RequestAuthorizeSignature {

    /**
     * Regex which matches any of the sequences that we need to fix up after
     * URLEncoder.encode().
     */
    private static final Pattern ENCODED_CHARACTERS_PATTERN;
    private static final TimeZone GMT = TimeZone.getTimeZone("GMT");
    private static final DateFormat timestampFormat;
    private static final DateFormat dateFormat;

    static {
        StringBuilder pattern = new StringBuilder();

        pattern
            .append(Pattern.quote("+"))
            .append("|")
            .append(Pattern.quote("*"))
            .append("|")
            .append(Pattern.quote("%7E"))
            .append("|")
            .append(Pattern.quote("%2F"));

        ENCODED_CHARACTERS_PATTERN = Pattern.compile(pattern.toString());

        timestampFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        timestampFormat.setTimeZone(GMT);

        dateFormat = new SimpleDateFormat("yyyyMMdd");
        dateFormat.setTimeZone(GMT);

    }

    // Specifying a default for how to parse the service and region in this way allows
    // tests or other downstream services to not have to use guice overrides.
    @ImplementedBy(ServiceAndRegion.AWSServiceAndRegion.class)
    public interface ServiceAndRegion {
        String service();

        String region(String host);

        static final class AWSServiceAndRegion implements ServiceAndRegion {
            private final String service;

            @Inject
            AWSServiceAndRegion(ProviderMetadata provider) {
                this(provider.getEndpoint());
            }

            AWSServiceAndRegion(String endpoint) {
                this.service = AwsHostNameUtils.parseServiceName(URI.create(checkNotNull(endpoint, "endpoint")));
            }

            @Override
            public String service() {
                return service;
            }

            @Override
            public String region(String host) {
                return AwsHostNameUtils.parseRegionName(host, service());
            }
        }
    }

    private final SignatureWire signatureWire;
    private final String headerTag;
    // s3 api does not version query string parameters
    //    private final String apiVersion;
    private final Supplier<Credentials> creds;
    private final ServiceAndRegion serviceAndRegion;
    private final javax.inject.Provider<Date> timestampProvider;
    private final Crypto crypto;

    @Inject
    public RequestAuthorizeSignatureV4(
        SignatureWire signatureWire,
        @Named(PROPERTY_S3_VIRTUAL_HOST_BUCKETS) boolean isVhostStyle,
        @Named(PROPERTY_HEADER_TAG) String headerTag,
        @Provider Supplier<Credentials> creds,
        @TimeStamp javax.inject.Provider<Date> timestampProvider,
        ServiceAndRegion serviceAndRegion,
        Crypto crypto
    ) {

        this.signatureWire = signatureWire;
        this.headerTag = headerTag;
        this.creds = creds;
        this.timestampProvider = timestampProvider;
        this.serviceAndRegion = serviceAndRegion;
        this.crypto = crypto;
    }

    @Override
    public HttpRequest filter(HttpRequest request) throws HttpException {
        checkArgument(request.getHeaders().containsKey(HOST), "request is not ready to sign; host not present");
        String host = request.getFirstHeaderOrNull(HOST);

//        checkArgument(decodedParams.containsKey(ACTION), "request is not ready to sign; Action not present %s", form);
        Date date = timestampProvider.get();
        String timestamp = timestampFormat.format(date);
        String datestamp = dateFormat.format(date);

        String service = serviceAndRegion.service();
        String region = serviceAndRegion.region(host);
        String credentialScope = Joiner.on('/').join(datestamp, region, service, "aws4_request");
        Payload payload = request.getPayload();
        URI endpoint = request.getEndpoint();
        // Default Content Type
        String contentType = MediaType.FORM_DATA.toString();
        if (payload != null
            && payload.getContentMetadata() != null
            && payload.getContentMetadata().getContentType() != null) {
            contentType = payload.getContentMetadata().getContentType();
        }
        // content-type is not a required signing param. However, examples use this, so we include it to ease testing.
        ImmutableMap.Builder<String, String> signedHeadersBuilder = ImmutableMap.<String, String>builder() //
            .put("content-type", contentType) //
            .put("host", host);

        if (request.getHeaders().containsKey(HttpHeaders.USER_AGENT)) {
            signedHeadersBuilder.put("user-agent", request.getFirstHeaderOrNull(HttpHeaders.USER_AGENT));
        }
        appendAmzHeaders(request, signedHeadersBuilder);

        HttpRequest.Builder<?> requestBuilder = request.toBuilder() //
            .removeHeader(AUTHORIZATION) // remove Authorization
            .removeHeader(DATE) // remove date
            .replaceHeader("X-Amz-Date", timestamp);
        requestBuilder.replaceHeader(HttpHeaders.CONTENT_TYPE, contentType);

        Credentials credentials = creds.get();

        if (credentials instanceof SessionCredentials) {
            String token = SessionCredentials.class.cast(credentials).getSessionToken();
            requestBuilder.replaceHeader("X-Amz-Security-Token", token);
            signedHeadersBuilder.put("x-amz-security-token", token);
        }

        String contentSha256 = calculateContentHash(requestBuilder, request.getMethod(), endpoint, payload);
        if ("required".equals(requestBuilder.build().getFirstHeaderOrNull("x-amz-content-sha256"))) {
            requestBuilder.replaceHeader("x-amz-content-sha256", contentSha256);
            signedHeadersBuilder.put("x-amz-content-sha256", contentSha256);
        }

        // put x-amz-date
        signedHeadersBuilder.put("x-amz-date", timestamp);


        requestBuilder.payload(payload);

        ImmutableMap<String, String> signedHeaders = signedHeadersBuilder.build();

        String stringToSign = createStringToSign(requestBuilder.build(), signedHeaders, credentialScope);
        signatureWire.getWireLog().debug("<< " + stringToSign);

        byte[] signatureKey = signatureKey(credentials.credential, datestamp, region, service);
        String signature = base16().lowerCase().encode(hmacSHA256(stringToSign, signatureKey));

        StringBuilder authorization = new StringBuilder("AWS4-HMAC-SHA256 ");
        authorization.append("Credential=").append(credentials.identity).append('/').append(credentialScope).append(", ");
        authorization.append("SignedHeaders=").append(Joiner.on(';').join(signedHeaders.keySet())).append(", ");
        authorization.append("Signature=").append(signature);

        return requestBuilder.addHeader(AUTHORIZATION, authorization.toString()).build();
    }

    // append all of 'x-amz-*' headers
    void appendAmzHeaders(HttpRequest request, ImmutableMap.Builder<String, String> signedHeadersBuilder) {
        for (Map.Entry<String, String> header : request.getHeaders().entries()) {
            String key = header.getKey();
            if (key.startsWith("x-" + headerTag + "-")) {
                signedHeadersBuilder.put(key.toLowerCase(), header.getValue());
            }
        }
    }

    // calculate content hash
    protected String calculateContentHash(
        HttpRequest.Builder requestBuilder,
        String method,
        URI endpoint,
        Payload payload
    ) {
        InputStream payloadStream;
        try {
            payloadStream = usePayloadForQueryParameters(method, payload) ?
                getQueryStringContent(endpoint)
                : getPayloadContentWithoutQueryString(payload);
        } catch (IOException e) {
            throw new HttpException("Unable to open stream before calculate AWS4 signature", e);
        }
        String contentSha256 = base16().lowerCase().encode(hash(payloadStream));
        try {
            payloadStream.reset();
        } catch (IOException e) {
            throw new HttpException(
                "Unable to close stream after calculating AWS4 signature",
                e);
        }
        return contentSha256;
    }

    protected InputStream getPayloadContentWithoutQueryString(Payload payload) throws IOException {
        if (payload == null) {
            return new ByteArrayInputStream(new byte[0]);
        }
        return payload.openStream();
    }

    protected InputStream getQueryStringContent(URI endpoint) {
        String encodedParameters = endpoint.getQuery();
        if (encodedParameters == null) {
            return new ByteArrayInputStream(new byte[0]);
        }
        return toInputStream(encodedParameters);
    }

    public static boolean usePayloadForQueryParameters(String method, Payload payload) {
        boolean requestIsPOST = "POST".equals(method);
        boolean requestHasNoPayload = payload == null;

        return requestIsPOST && requestHasNoPayload;
    }

    byte[] signatureKey(String secretKey, String datestamp, String region, String service) {
        byte[] kSecret = ("AWS4" + secretKey).getBytes(UTF_8);
        byte[] kDate = hmacSHA256(datestamp, kSecret);
        byte[] kRegion = hmacSHA256(region, kDate);
        byte[] kService = hmacSHA256(service, kRegion);
        byte[] kSigning = hmacSHA256("aws4_request", kService);
        return kSigning;
    }

    byte[] hmacSHA256(String toSign, byte[] key) {
        try {
            ByteProcessor<byte[]> hmacSHA256 = asByteProcessor(crypto.hmacSHA256(key));
            return readBytes(toInputStream(toSign), hmacSHA256);
        } catch (IOException e) {
            throw new HttpException("read bytes error", e);
        } catch (InvalidKeyException e) {
            throw new HttpException("invalid key", e);
        }
    }

    protected byte[] hash(InputStream input) throws HTTPException {
        try {
            Hasher hasher = Hashing.sha256().newHasher();
            byte[] buffer = new byte[4096];
            int r;
            while ((r = input.read(buffer)) != -1) {
                hasher.putBytes(buffer, 0, r);
            }
            return hasher.hash().asBytes();
        } catch (Exception e) {
            throw new HttpException(
                "Unable to compute hash while signing request: "
                    + e.getMessage(), e);
        }
    }

    protected byte[] hash(String input) throws HTTPException {
        return hash(new ByteArrayInputStream(input.getBytes(UTF_8)));
    }

    String createStringToSign(HttpRequest request, Map<String, String> signedHeaders, String credentialScope) {
        StringBuilder canonicalRequest = new StringBuilder();

        // HTTPRequestMethod + '\n' +
        canonicalRequest.append(request.getMethod()).append("\n");

        // CanonicalURI + '\n' +
        canonicalRequest.append(request.getEndpoint().getPath()).append("\n");

        // CanonicalQueryString + '\n' +
        if (request.getEndpoint().getQuery() != null) {
            canonicalRequest.append(getCanonicalizedQueryString(request.getEndpoint().getQuery()));
        }
        canonicalRequest.append("\n");

        // CanonicalHeaders + '\n' +
        for (Map.Entry<String, String> entry : signedHeaders.entrySet()) {
            canonicalRequest.append(entry.getKey()).append(':').append(entry.getValue()).append('\n');
        }
        canonicalRequest.append("\n");

        // SignedHeaders + '\n' +
        canonicalRequest.append(Joiner.on(';').join(signedHeaders.keySet())).append('\n');

        // HexEncode(Hash(Payload))
        canonicalRequest.append(signedHeaders.get("x-amz-content-sha256"));

        signatureWire.getWireLog().debug("<<", canonicalRequest);

        StringBuilder toSign = new StringBuilder();
        // Algorithm + '\n' +
        toSign.append("AWS4-HMAC-SHA256").append('\n');
        // RequestDate + '\n' +
        toSign.append(signedHeaders.get("x-amz-date")).append('\n');
        // CredentialScope + '\n' +
        toSign.append(credentialScope).append('\n');
        // HexEncode(Hash(CanonicalRequest))
        toSign.append(base16().lowerCase().encode(hash(canonicalRequest.toString())));

        return toSign.toString();
    }

    /**
     * Examines the specified query string parameters and returns a
     * canonicalized form.
     * <p/>
     * The canonicalized query string is formed by first sorting all the query
     * string parameters, then URI encoding both the key and value and then
     * joining them, in order, separating key value pairs with an '&'.
     *
     * @param queryString The query string parameters to be canonicalized.
     * @return A canonicalized form for the specified query string parameters.
     */
    protected String getCanonicalizedQueryString(String queryString) {
        Multimap<String, String> params = queryParser().apply(queryString);
        SortedMap<String, String> sorted = new TreeMap<String, String>();
        if (params == null) {
            return "";
        }
        Iterator<Map.Entry<String, String>> pairs = params.entries().iterator();
        while (pairs.hasNext()) {
            Map.Entry<String, String> pair = pairs.next();
            String key = pair.getKey();
            String value = pair.getValue();
            sorted.put(urlEncode(key), urlEncode(value));
        }

        return Joiner.on("&").withKeyValueSeparator("=").join(sorted);
    }

    /**
     * Encode a string for use in the path of a URL; uses URLEncoder.encode,
     * (which encodes a string for use in the query portion of a URL), then
     * applies some postfilters to fix things up per the RFC. Can optionally
     * handle strings which are meant to encode a path (ie include '/'es
     * which should NOT be escaped).
     *
     * @param value the value to encode
     * @return the encoded value
     */
    public static String urlEncode(final String value) {
        if (value == null) {
            return "";
        }

        String encoded = UrlEscapers.urlFormParameterEscaper().escape(value);

        Matcher matcher = ENCODED_CHARACTERS_PATTERN.matcher(encoded);
        StringBuffer buffer = new StringBuffer(encoded.length());

        while (matcher.find()) {
            String replacement = matcher.group(0);

            if ("+".equals(replacement)) {
                replacement = "%20";
            } else if ("*".equals(replacement)) {
                replacement = "%2A";
            } else if ("%7E".equals(replacement)) {
                replacement = "~";
            }

            matcher.appendReplacement(buffer, replacement);
        }

        matcher.appendTail(buffer);
        return buffer.toString();
    }

    // Authenticating Requests by Using Query Parameters (AWS Signature Version 4)


    // Using query parameters to authenticate requests is useful when you want to express a request entirely in a URL.
    // This method is also referred as presigning a URL.
    // Presigned URLs enable you to grant temporary access to your Amazon S3 resources.
    // The end user can then enter the presigned URL in his or her browser to access the specific Amazon S3 resource.
    // You can also use presigned URLs to embed clickable links in HTML.
    // For example, you might store videos in an Amazon S3 bucket and make them available on your website by using presigned URLs.
    // Identifies the version of AWS Signature and the algorithm that you used to calculate the signature.

    public HttpRequest signForTemporaryAccess(HttpRequest request, long timeInSeconds) {
        checkArgument(request.getHeaders().containsKey(HOST), "request is not ready to sign; host not present");

        String method = request.getMethod();
        String host = request.getFirstHeaderOrNull(HOST);

        Date date = timestampProvider.get();
        String timestamp = timestampFormat.format(date);
        String datestamp = dateFormat.format(date);

        String service = serviceAndRegion.service();
        String region = serviceAndRegion.region(host);
        String credentialScope = Joiner.on('/').join(datestamp, region, service, "aws4_request");

        Uris.UriBuilder endpointBuilder = Uris.uriBuilder(request.getEndpoint());

        // different with signature with Authorization header
        HttpRequest.Builder<?> requestBuilder = request.toBuilder() //
            // sign for temporary access use query string parameter:
            // X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date, X-Amz-Expires, X-Amz-SignedHeaders, X-Amz-Signature
            // remove Authorization, x-amz-content-sha256, X-Amz-Date headers
            .removeHeader(AUTHORIZATION_HEADER)
            .removeHeader(AMZ_CONTENT_SHA256_HEADER)
            .removeHeader(AMZ_DATE_HEADER);

        // Canonical Headers
        // must include the HTTP host header.
        // If you plan to include any of the x-amz-* headers, these headers must also be added for signature calculation.
        // You can optionally add all other headers that you plan to include in your request.
        // For added security, you should sign as many headers as possible.
        ImmutableMap.Builder<String, String> signedHeadersBuilder = ImmutableSortedMap.<String, String>naturalOrder() //
            .put("host", host);

        ImmutableMap<String, String> signedHeaders = signedHeadersBuilder.build();

        Credentials credentials = creds.get();

        if (credentials instanceof SessionCredentials) {
            String token = SessionCredentials.class.cast(credentials).getSessionToken();
            // different with signature with Authorization header
            endpointBuilder.replaceQuery("X-Amz-Security-Token", token);
        }

        // set payload with origin request payload
        requestBuilder.payload(request.getPayload());

        // X-Amz-Algorithm=HMAC-SHA256
        endpointBuilder.replaceQuery(AMZ_ALGORITHM_PARAM, AwsSignatureV4Constants.AMZ_ALGORITHM_HMAC_SHA256);

        // X-Amz-Credential=<your-access-key-id>/<date>/<AWS-region>/<AWS-service>/aws4_request.
        String credential = Joiner.on("/").join(credentials.identity, credentialScope);
        endpointBuilder.replaceQuery(AMZ_CREDENTIAL_PARAM, credential);

        // X-Amz-Date=ISO 8601 format, for example, 20130721T201207Z
        endpointBuilder.replaceQuery(AMZ_DATE_PARAM, timestamp);

        // X-Amz-Expires=time in seconds
        endpointBuilder.replaceQuery(AMZ_EXPIRES_PARAM, String.valueOf(timeInSeconds));

        // X-Amz-SignedHeaders=HTTP host header is required.
        endpointBuilder.replaceQuery(AMZ_SIGNEDHEADERS_PARAM, Joiner.on(';').join(signedHeaders.keySet()));

        URI endpoint = endpointBuilder.build();
        String stringToSign = createStringToSignForSignatureQueryParam(method, endpoint, timestamp, signedHeaders, credentialScope);

        signatureWire.getWireLog().debug("<< " + stringToSign);

        requestBuilder.endpoint(endpoint);

        byte[] signatureKey = signatureKey(credentials.credential, datestamp, region, service);
        String signature = base16().lowerCase().encode(hmacSHA256(stringToSign, signatureKey));

        // X-Amz-Signature=Signature
        requestBuilder.replaceQueryParam(AMZ_SIGNATURE_PARAM, signature);

        return requestBuilder.build();
    }

    String createStringToSignForSignatureQueryParam(String method, URI endpoint, String timestamp, Map<String, String> signedHeaders, String credentialScope) {
        StringBuilder canonicalRequest = new StringBuilder();

        // HTTPRequestMethod + '\n' +
        canonicalRequest.append(method).append("\n");

        // CanonicalURI + '\n' +
        canonicalRequest.append(endpoint.getPath()).append("\n");

        // CanonicalQueryString + '\n' +
        if (endpoint.getQuery() != null) {
            canonicalRequest.append(getCanonicalizedQueryString(endpoint.getQuery()));
        }
        canonicalRequest.append("\n");

        // CanonicalHeaders + '\n' +
        for (Map.Entry<String, String> entry : signedHeaders.entrySet()) {
            canonicalRequest.append(entry.getKey()).append(':').append(entry.getValue()).append('\n');
        }
        canonicalRequest.append("\n");

        // SignedHeaders + '\n' +
        canonicalRequest.append(Joiner.on(';').join(signedHeaders.keySet())).append('\n');

        // UNSIGNED_PAYLOAD
        canonicalRequest.append(UNSIGNED_PAYLOAD);

        signatureWire.getWireLog().debug("<<", canonicalRequest);

        StringBuilder toSign = new StringBuilder();
        // Algorithm + '\n' +
        toSign.append("AWS4-HMAC-SHA256").append('\n');
        // RequestDate + '\n' +
        toSign.append(timestamp).append('\n');
        // CredentialScope + '\n' +
        toSign.append(credentialScope).append('\n');
        // HexEncode(Hash(CanonicalRequest))
        toSign.append(base16().lowerCase().encode(hash(canonicalRequest.toString())));

        return toSign.toString();
    }

}
