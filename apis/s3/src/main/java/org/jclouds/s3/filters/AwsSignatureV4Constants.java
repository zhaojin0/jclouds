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

/**
 * AWS Signature Version 4 Constants.
 */
public abstract class AwsSignatureV4Constants {

    // AWS authorization header key
    public static final String AUTHORIZATION_HEADER = "Authorization";

    // AWS content sha256 header key
    public static final String AMZ_CONTENT_SHA256_HEADER = "x-amz-content-sha256";

    // AWS date header key
    public static final String AMZ_DATE_HEADER = "X-Amz-Date";

    public static final String AMZ_SECURITY_TOKEN_HEADER= "X-Amz-Security-Token";

    // For AWS Signature Version 4, you set this parameter value to "AWS4-HMAC-SHA256". This string identifies AWS Signature Version 4 (AWS4) and the HMAC-SHA256 algorithm (HMAC-SHA256).
    public static final String AMZ_ALGORITHM_PARAM = "X-Amz-Algorithm";
    public static final String AMZ_ALGORITHM_HMAC_SHA256 = "AWS4-HMAC-SHA256";

    // In addition to your access key ID, this parameter also provides scope information identifying the region and service for which the signature is valid. This value should match the scope that you use to calculate the signing key, as discussed in the following section.
    // The general form for this parameter value is as follows:
    // <your-access-key-id>/<date>/<AWS-region>/<AWS-service>/aws4_request.
    // For example:
    // AKIAIOSFODNN7EXAMPLE/20130721/us-east-1/s3/aws4_request.
    // For Amazon S3, the AWS-service string is "s3". For a list of AWS-region strings, go to Regions and Endpoints in the Amazon Web Services General Reference
    public static final String AMZ_CREDENTIAL_PARAM = "X-Amz-Credential";

    //This header can be used in the following scenarios:
    //    Provide security tokens for Amazon DevPay operations—Each request that uses Amazon DevPay requires two x-amz-security-token headers: one for the product token and one for the user token. When Amazon S3 receives an authenticated request, it compares the computed signature with the provided signature. Improperly formatted multi-value headers used to calculate a signature can cause authentication issues
    //    Provide security token when using temporary security credentials—When making requests using temporary security credentials you obtained from IAM you must provide a security token using this header. To learn more about temporary security credentials, go to Making Requests.
    //
    // This header is required for requests that use Amazon DevPay and requests that are signed using temporary security credentials.
    public static final String AMZ_SECURITY_TOKEN_PARAM = AMZ_SECURITY_TOKEN_HEADER;

    // The date in ISO 8601 format, for example, 20130721T201207Z. This value must match the date value used to calculate the signature.
    public static final String AMZ_DATE_PARAM = AMZ_DATE_HEADER;

    // Provides the time period, in seconds, for which the generated presigned URL is valid. For example, 86400 (24 hours). This value is an integer. The minimum value you can set is 1, and the maximum is 604800 (seven days).
    // A presigned URL can be valid for a maximum of seven days because the signing key you use in signature calculation is valid for up to seven days.
    public static final String AMZ_EXPIRES_PARAM = "X-Amz-Expires";

    // Lists the headers that you used to calculate the signature.
    // The HTTP host header is required. Any x-amz-* headers that you plan to add to the request are also required for signature calculation.
    // In general, for added security, you should sign all the request headers that you plan to include in your request.
    // X-Amz-Signature Provides the signature to authenticate your request.
    // This signature must match the signature Amazon S3 calculates; otherwise, Amazon S3 denies the request. For example, 733255ef022bec3f2a8701cd61d4b371f3f28c9f193a1f02279211d48d5193d7
    public static final String AMZ_SIGNEDHEADERS_PARAM = "X-Amz-SignedHeaders";

    //    Lists the headers that you used to calculate the signature.
    //    The HTTP host header is required. Any x-amz-* headers that you plan to add to the request are also required for signature calculation. In general, for added security, you should sign all the request headers that you plan to include in your request.
    //    X-Amz-Signature
    //    Provides the signature to authenticate your request. This signature must match the signature Amazon S3 calculates; otherwise, Amazon S3 denies the request. For example, 733255ef022bec3f2a8701cd61d4b371f3f28c9f193a1f02279211d48d5193d7
    public static final String AMZ_SIGNATURE_PARAM = "X-Amz-Signature";

    // You don't include a payload hash in the Canonical Request, because when you create a presigned URL,
    // you don't know anything about the payload. Instead, you use a constant string "UNSIGNED-PAYLOAD".
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

    private AwsSignatureV4Constants() {
    }
}
