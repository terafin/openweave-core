/*
 *
 *    Copyright (c) 2020 Google LLC.
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "ToolCommon.h"
#include "MockCPClient.h"
#include "MockDDServer.h"
#include <Weave/Core/WeaveTLV.h>
#include <Weave/Profiles/common/CommonProfile.h>
#include <Weave/Profiles/security/WeaveCert.h>
#include <Weave/Profiles/security/WeavePrivateKey.h>
#include <Weave/Profiles/security/WeaveSig.h>
#include <Weave/Profiles/service-directory/ServiceDirectory.h>
#include "CASEOptions.h"

using namespace ::nl;
using namespace ::nl::Weave;
using namespace ::nl::Weave::TLV;
using namespace ::nl::Weave::Profiles;
using namespace ::nl::Weave::Profiles::Security;
using namespace ::nl::Weave::Profiles::Security::CertProvisioning;

MockCertificateProvisioningClient::MockCertificateProvisioningClient(void)
{
    mBinding = NULL;

    mDeviceId = kNodeIdNotSpecified;
    mDeviceCert = NULL;
    mDeviceCertLen = 0;
    mDeviceIntermediateCACerts = NULL;
    mDeviceIntermediateCACertsLen = 0;
    mDevicePrivateKey = NULL;
    mDevicePrivateKeyLen = 0;
}

/**
 * Initialize certificate provisioning client.
 *
 *  @param[in]  exchangeMgr          A pointer to the system Weave Exchange Manager.
 *  @param[in]  reqType              Get certificate request type.
 *  @param[in]  encodeReqAuthInfo    A pointer to a function that generates ECDSA signature on the given
 *                                   certificate hash using operational device private key.
 *
 *  @retval #WEAVE_NO_ERROR          If certificate provisioning client was successfully initialized.
 */
// WEAVE_ERROR MockCertificateProvisioningClient::Init(WeaveExchangeManager *exchangeMgr, uint8_t reqType,
//                                                     EncodeReqAuthInfoFunct encodeReqAuthInfo,
//                                                     HandleCertificateProvisioningResultFunct onCertProvDone)
WEAVE_ERROR MockCertificateProvisioningClient::Init(WeaveExchangeManager *exchangeMgr)
{
    ExchangeMgr = exchangeMgr;
    // mReqType = reqType;
    // mEncodeReqAuthInfo = encodeReqAuthInfo;
    // mOnCertProvDone = onCertProvDone;
    mReqType = WeaveCertProvEngine::kReqType_NotSpecified;
    mEncodeReqAuthInfo = NULL;
    mOnCertProvDone = NULL;

    // mDoMfrAttest = (reqType == WeaveCertProvEngine::kReqType_GetInitialOpDeviceCert) ? true : false;

    static char defaultWOCAServerAddr[64];
    strcpy(defaultWOCAServerAddr, "127.0.0.1");

#if WEAVE_CONFIG_ENABLE_TARGETED_LISTEN
    if (exchangeMgr->FabricState->ListenIPv4Addr == IPAddress::Any)
    {
        if (exchangeMgr->FabricState->ListenIPv6Addr != IPAddress::Any)
            exchangeMgr->FabricState->ListenIPv6Addr.ToString(defaultWOCAServerAddr, sizeof(defaultWOCAServerAddr));
    }
    else
        exchangeMgr->FabricState->ListenIPv4Addr.ToString(defaultWOCAServerAddr, sizeof(defaultWOCAServerAddr));
#endif

    WOCAServerEndPointId = exchangeMgr->FabricState->LocalNodeId;
    WOCAServerAddr = defaultWOCAServerAddr;

    mBinding = NULL;

    mDeviceId = kNodeIdNotSpecified;
    mDeviceCert = NULL;
    mDeviceCertLen = 0;
    mDeviceIntermediateCACerts = NULL;
    mDeviceIntermediateCACertsLen = 0;
    mDevicePrivateKey = NULL;
    mDevicePrivateKeyLen = 0;

    return WEAVE_NO_ERROR;
}

WEAVE_ERROR MockCertificateProvisioningClient::Shutdown(void)
{
    ClearOperationalDeviceCredentials();

    return WEAVE_NO_ERROR;
}

void MockCertificateProvisioningClient::Reset(void)
{
    ClearOperationalDeviceCredentials();
}

void MockCertificateProvisioningClient::Preconfig(void)
{
    // This dummy service config object contains the following information:
    //
    //    Trusted Certificates:
    //        The Nest Development Root Certificate
    //        A dummy "account" certificate with a common name of "DUMMY-ACCOUNT-ID" (see below)
    //
    //    Directory End Point:
    //        Endpoint Id: 18B4300200000001 (the service directory endpoint)
    //        Endpoint Host Name: frontdoor.integration.nestlabs.com
    //        Endpoint Port: 11095 (the weave default port)
    //
    // The dummy account certificate is:
    //
    //    1QAABAABADABCE4vMktB1zrbJAIENwMsgRBEVU1NWS1BQ0NPVU5ULUlEGCYEy6j6GyYFSzVPQjcG
    //    LIEQRFVNTVktQUNDT1VOVC1JRBgkBwImCCUAWiMwCjkEK9nbWmLvurFTKg+ZY7eKMMWKQSmlGU5L
    //    C/N+2sXpszXwdRhtSV2GxEQlB0G006nv7rQq1gpdneA1gykBGDWCKQEkAgUYNYQpATYCBAIEARgY
    //    NYEwAghCPJVfRh5S2xg1gDACCEI8lV9GHlLbGDUMMAEdAIphhmI9F7LSz9JtOT3kJWngkeoFanXO
    //    3UXrg88wAhx0tCukbRRlt7dxmlqvZNKIYG6zsaAxypJvyvJDGBg=
    //
    // The corresponding private key is:
    //
    //    1QAABAACACYBJQBaIzACHLr840+Gv3w4EnAr+aMQv0+b8+8wD6VETUI6Z2owAzkEK9nbWmLvurFT
    //    Kg+ZY7eKMMWKQSmlGU5LC/N+2sXpszXwdRhtSV2GxEQlB0G006nv7rQq1gpdneAY
    //
    // The following is a fabric access token containing the dummy account certificate and
    // private key.  This can be used to authenticate to the mock device when it has been
    // configured to use the dummy service config.
    //
    //    1QAABAAJADUBMAEITi8yS0HXOtskAgQ3AyyBEERVTU1ZLUFDQ09VTlQtSUQYJgTLqPobJgVLNU9C
    //    NwYsgRBEVU1NWS1BQ0NPVU5ULUlEGCQHAiYIJQBaIzAKOQQr2dtaYu+6sVMqD5ljt4owxYpBKaUZ
    //    TksL837axemzNfB1GG1JXYbERCUHQbTTqe/utCrWCl2d4DWDKQEYNYIpASQCBRg1hCkBNgIEAgQB
    //    GBg1gTACCEI8lV9GHlLbGDWAMAIIQjyVX0YeUtsYNQwwAR0AimGGYj0XstLP0m05PeQlaeCR6gVq
    //    dc7dReuDzzACHHS0K6RtFGW3t3GaWq9k0ohgbrOxoDHKkm/K8kMYGDUCJgElAFojMAIcuvzjT4a/
    //    fDgScCv5oxC/T5vz7zAPpURNQjpnajADOQQr2dtaYu+6sVMqD5ljt4owxYpBKaUZTksL837axemz
    //    NfB1GG1JXYbERCUHQbTTqe/utCrWCl2d4BgY
    //
    //
    static const char dummyAccountId[] = "DUMMY-ACCOUNT-ID";
    static const uint8_t dummyServiceConfig[] =
    {
        0xd5, 0x00, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x36, 0x01, 0x15, 0x30, 0x01, 0x08, 0x4e, 0x2f, 0x32,
        0x4b, 0x41, 0xd7, 0x3a, 0xdb, 0x24, 0x02, 0x04, 0x37, 0x03, 0x2c, 0x81, 0x10, 0x44, 0x55, 0x4d,
        0x4d, 0x59, 0x2d, 0x41, 0x43, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x2d, 0x49, 0x44, 0x18, 0x26, 0x04,
        0xcb, 0xa8, 0xfa, 0x1b, 0x26, 0x05, 0x4b, 0x35, 0x4f, 0x42, 0x37, 0x06, 0x2c, 0x81, 0x10, 0x44,
        0x55, 0x4d, 0x4d, 0x59, 0x2d, 0x41, 0x43, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x2d, 0x49, 0x44, 0x18,
        0x24, 0x07, 0x02, 0x26, 0x08, 0x25, 0x00, 0x5a, 0x23, 0x30, 0x0a, 0x39, 0x04, 0x2b, 0xd9, 0xdb,
        0x5a, 0x62, 0xef, 0xba, 0xb1, 0x53, 0x2a, 0x0f, 0x99, 0x63, 0xb7, 0x8a, 0x30, 0xc5, 0x8a, 0x41,
        0x29, 0xa5, 0x19, 0x4e, 0x4b, 0x0b, 0xf3, 0x7e, 0xda, 0xc5, 0xe9, 0xb3, 0x35, 0xf0, 0x75, 0x18,
        0x6d, 0x49, 0x5d, 0x86, 0xc4, 0x44, 0x25, 0x07, 0x41, 0xb4, 0xd3, 0xa9, 0xef, 0xee, 0xb4, 0x2a,
        0xd6, 0x0a, 0x5d, 0x9d, 0xe0, 0x35, 0x83, 0x29, 0x01, 0x18, 0x35, 0x82, 0x29, 0x01, 0x24, 0x02,
        0x05, 0x18, 0x35, 0x84, 0x29, 0x01, 0x36, 0x02, 0x04, 0x02, 0x04, 0x01, 0x18, 0x18, 0x35, 0x81,
        0x30, 0x02, 0x08, 0x42, 0x3c, 0x95, 0x5f, 0x46, 0x1e, 0x52, 0xdb, 0x18, 0x35, 0x80, 0x30, 0x02,
        0x08, 0x42, 0x3c, 0x95, 0x5f, 0x46, 0x1e, 0x52, 0xdb, 0x18, 0x35, 0x0c, 0x30, 0x01, 0x1d, 0x00,
        0x8a, 0x61, 0x86, 0x62, 0x3d, 0x17, 0xb2, 0xd2, 0xcf, 0xd2, 0x6d, 0x39, 0x3d, 0xe4, 0x25, 0x69,
        0xe0, 0x91, 0xea, 0x05, 0x6a, 0x75, 0xce, 0xdd, 0x45, 0xeb, 0x83, 0xcf, 0x30, 0x02, 0x1c, 0x74,
        0xb4, 0x2b, 0xa4, 0x6d, 0x14, 0x65, 0xb7, 0xb7, 0x71, 0x9a, 0x5a, 0xaf, 0x64, 0xd2, 0x88, 0x60,
        0x6e, 0xb3, 0xb1, 0xa0, 0x31, 0xca, 0x92, 0x6f, 0xca, 0xf2, 0x43, 0x18, 0x18, 0x15, 0x30, 0x01,
        0x09, 0x00, 0xa8, 0x34, 0x22, 0xe9, 0xd9, 0x75, 0xe4, 0x55, 0x24, 0x02, 0x04, 0x57, 0x03, 0x00,
        0x27, 0x13, 0x01, 0x00, 0x00, 0xee, 0xee, 0x30, 0xb4, 0x18, 0x18, 0x26, 0x04, 0x95, 0x23, 0xa9,
        0x19, 0x26, 0x05, 0x15, 0xc1, 0xd2, 0x2c, 0x57, 0x06, 0x00, 0x27, 0x13, 0x01, 0x00, 0x00, 0xee,
        0xee, 0x30, 0xb4, 0x18, 0x18, 0x24, 0x07, 0x02, 0x24, 0x08, 0x15, 0x30, 0x0a, 0x31, 0x04, 0x78,
        0x52, 0xe2, 0x9c, 0x92, 0xba, 0x70, 0x19, 0x58, 0x46, 0x6d, 0xae, 0x18, 0x72, 0x4a, 0xfb, 0x43,
        0x0d, 0xf6, 0x07, 0x29, 0x33, 0x0d, 0x61, 0x55, 0xe5, 0x65, 0x46, 0x8e, 0xba, 0x0d, 0xa5, 0x3f,
        0xb5, 0x17, 0xc0, 0x47, 0x64, 0x44, 0x02, 0x18, 0x4f, 0xa8, 0x11, 0x24, 0x50, 0xd4, 0x7b, 0x35,
        0x83, 0x29, 0x01, 0x29, 0x02, 0x18, 0x35, 0x82, 0x29, 0x01, 0x24, 0x02, 0x60, 0x18, 0x35, 0x81,
        0x30, 0x02, 0x08, 0x42, 0x0c, 0xac, 0xf6, 0xb4, 0x64, 0x71, 0xe6, 0x18, 0x35, 0x80, 0x30, 0x02,
        0x08, 0x42, 0x0c, 0xac, 0xf6, 0xb4, 0x64, 0x71, 0xe6, 0x18, 0x35, 0x0c, 0x30, 0x01, 0x19, 0x00,
        0xbe, 0x0e, 0xda, 0xa1, 0x63, 0x5a, 0x8e, 0xf1, 0x52, 0x17, 0x45, 0x80, 0xbd, 0xdc, 0x94, 0x12,
        0xd4, 0xcc, 0x1c, 0x2c, 0x33, 0x4e, 0x29, 0xdc, 0x30, 0x02, 0x19, 0x00, 0x8b, 0xe7, 0xee, 0x2e,
        0x11, 0x17, 0x14, 0xae, 0x92, 0xda, 0x2b, 0x3b, 0x6d, 0x2f, 0xd7, 0x5d, 0x9e, 0x5f, 0xcd, 0xb8,
        0xba, 0x2f, 0x65, 0x76, 0x18, 0x18, 0x18, 0x35, 0x02, 0x27, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02,
        0x30, 0xb4, 0x18, 0x36, 0x02, 0x15, 0x2c, 0x01, 0x22, 0x66, 0x72, 0x6f, 0x6e, 0x74, 0x64, 0x6f,
        0x6f, 0x72, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6e,
        0x65, 0x73, 0x74, 0x6c, 0x61, 0x62, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x18, 0x18, 0x18, 0x18
    };

    // ClearPersistedService();
    // PersistNewService(0x18B4300100000001ULL, dummyAccountId, strlen(dummyAccountId), dummyServiceConfig, sizeof(dummyServiceConfig));
}

/**
 *  Handler for Certificate Provisioning Client API events.
 *
 *  @param[in]  appState    A pointer to application-defined state information associated with the client object.
 *  @param[in]  eventType   Event ID passed by the event callback.
 *  @param[in]  inParam     Reference of input event parameters passed by the event callback.
 *  @param[in]  outParam    Reference of output event parameters passed by the event callback.
 *
 */
void MockCertificateProvisioningClient::CertProvClientEventHandler(void * appState, WeaveCertProvEngine::EventType eventType, const WeaveCertProvEngine::InEventParam & inParam, WeaveCertProvEngine::OutEventParam & outParam)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    MockCertificateProvisioningClient * client = static_cast<MockCertificateProvisioningClient *>(appState);
    WeaveCertProvEngine * certProvEngine = inParam.Source;

    switch (eventType)
    {
    case WeaveCertProvEngine::kEvent_PrepareAuthorizeInfo:
    {
        if (client->mEncodeReqAuthInfo != NULL)
        {
            printf("Preparing authorization information for the GetCertificateRequest message");

            err = client->mEncodeReqAuthInfo(client->mReqState, *inParam.PrepareAuthorizeInfo.Writer);
            SuccessOrExit(err);
        }
        break;
    }

    case WeaveCertProvEngine::kEvent_ResponseReceived:
    {
        if (inParam.ResponseReceived.ReplaceCert)
        {
            printf("Storing WOCA server issued operational device certificate");

            // Store service issued operational device certificate.
            err = client->StoreDeviceCertificate(inParam.ResponseReceived.Cert, inParam.ResponseReceived.CertLen);
            SuccessOrExit(err);

            if (inParam.ResponseReceived.RelatedCerts != NULL)
            {
                // Store device intermediate CA certificates related to the service issued operational device certificate.
                err = client->StoreDeviceIntermediateCACerts(inParam.ResponseReceived.RelatedCerts, inParam.ResponseReceived.RelatedCertsLen);
                SuccessOrExit(err);
            }
        }
        else
        {
            printf("WOCA server reported: no need to replace current operational device certificate");
        }

        certProvEngine->AbortCertificateProvisioning();
        break;
    }

    case WeaveCertProvEngine::kEvent_CommunicationError:
    {
        if (inParam.CommunicationError.Reason == WEAVE_ERROR_STATUS_REPORT_RECEIVED)
        {
            printf("Received status report from the WOCA server: %s",
                          nl::StatusReportStr(inParam.CommunicationError.RcvdStatusReport->mProfileId, inParam.CommunicationError.RcvdStatusReport->mStatusCode));
        }
        else
        {
            printf("Failed to prepare/send GetCertificateRequest message: %s", ErrorStr(inParam.CommunicationError.Reason));
        }

        certProvEngine->AbortCertificateProvisioning();
        break;
    }

    default:
        printf("Unrecognized certificate provisioning API event");

        certProvEngine->AbortCertificateProvisioning();
        break;
    }

exit:
    if (eventType == WeaveCertProvEngine::kEvent_PrepareAuthorizeInfo)
        outParam.PrepareAuthorizeInfo.Error = err;
    else if (eventType == WeaveCertProvEngine::kEvent_ResponseReceived)
        outParam.ResponseReceived.Error = err;
}

// ===== Methods that implement the WeaveNodeOpAuthDelegate interface

WEAVE_ERROR MockCertificateProvisioningClient::EncodeOpCert(TLVWriter & writer, uint64_t tag)
{
    WEAVE_ERROR err;
    uint8_t * cert = NULL;
    uint16_t certLen = 0;

    // Read the operational device certificate.
    err = GetDeviceCertificate(cert, certLen);
    SuccessOrExit(err);

    // Copy encoded operational device certificate.
    err = writer.CopyContainer(tag, cert, certLen);
    SuccessOrExit(err);

exit:
    return err;
}

WEAVE_ERROR MockCertificateProvisioningClient::EncodeOpRelatedCerts(TLVWriter & writer, uint64_t tag)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    uint8_t * icaCerts = NULL;
    uint16_t icaCertsLen = 0;

    // Read the operational device intermediate CA certificates.
    err = GetDeviceCertificate(icaCerts, icaCertsLen);
    SuccessOrExit(err);

    // Copy encoded operational device intermediate CA certificates.
    err = writer.CopyContainer(tag, icaCerts, icaCertsLen);
    SuccessOrExit(err);

exit:
    return err;
}

WEAVE_ERROR MockCertificateProvisioningClient::GenerateAndEncodeOpSig(const uint8_t * hash, uint8_t hashLen, TLVWriter & writer, uint64_t tag)
{
    WEAVE_ERROR err;
    uint8_t * privKey = NULL;
    uint16_t privKeyLen = 0;

    // Read the operational device private key.
    err = GetDevicePrivateKey(privKey, privKeyLen);
    SuccessOrExit(err);

    // Generate and encode operational device signature.
    err = GenerateAndEncodeWeaveECDSASignature(writer, tag, hash, hashLen, privKey, privKeyLen);
    SuccessOrExit(err);

exit:
    return err;
}

// ===== Methods that implement the WeaveNodeMfrAttestDelegate interface

WEAVE_ERROR MockCertificateProvisioningClient::EncodeMAInfo(TLVWriter & writer)
{
    WEAVE_ERROR err;
    uint8_t * cert = NULL;
    uint16_t certLen = 0;

    // Read the manufacturer assigned device certificate.
    err = GetManufacturerDeviceCertificate(cert, certLen);
    SuccessOrExit(err);

    // Copy encoded manufacturer attestation device certificate.
    err = writer.CopyContainer(ContextTag(kTag_GetCertReqMsg_MfrAttest_WeaveCert), cert, certLen);
    SuccessOrExit(err);

    // Determine if present and the length of the manufacturer assigned device intermediate CA certificates.
    err = GetManufacturerDeviceIntermediateCACerts(cert, certLen);
    if (cert == NULL && certLen == 0)
    {
        // Exit without error if manufacturer assigned intermediate CA certificates is not configured.
        ExitNow(err = WEAVE_NO_ERROR);
    }
    SuccessOrExit(err);

    // Copy encoded manufacturer attestation device intermediate CA certificates.
    err = writer.CopyContainer(ContextTag(kTag_GetCertReqMsg_MfrAttest_WeaveRelCerts), cert, certLen);
    SuccessOrExit(err);

exit:
    return err;
}

WEAVE_ERROR MockCertificateProvisioningClient::GenerateAndEncodeMASig(const uint8_t * data, uint16_t dataLen, TLVWriter & writer)
{
    WEAVE_ERROR err;
    uint8_t * privKey = NULL;
    uint16_t privKeyLen = 0;
    nl::Weave::Platform::Security::SHA256 sha256;
    uint8_t hash[SHA256::kHashLength];

    // Read the manufacturer attestation device private key.
    err = GetManufacturerDevicePrivateKey(privKey, privKeyLen);
    SuccessOrExit(err);

    // Calculate data hash.
    sha256.Begin();
    sha256.AddData(data, dataLen);
    sha256.Finish(hash);

    // Encode manufacturer attestation device signature algorithm: ECDSAWithSHA256.
    err = writer.Put(ContextTag(kTag_GetCertReqMsg_MfrAttestSigAlgo), static_cast<uint16_t>(ASN1::kOID_SigAlgo_ECDSAWithSHA256));
    SuccessOrExit(err);

    // Generate and encode manufacturer attestation device signature.
    err = GenerateAndEncodeWeaveECDSASignature(writer, ContextTag(kTag_GetCertReqMsg_MfrAttestSig_ECDSA),
                                               hash, SHA256::kHashLength, privKey, privKeyLen);
    SuccessOrExit(err);

exit:
    return err;
}

// ===== Members for internal use by this class only.

// void MockCertificateProvisioningClient::StartCertificateProvisioning(void * reqState)
WEAVE_ERROR MockCertificateProvisioningClient::StartCertificateProvisioning(uint8_t reqType, EncodeReqAuthInfoFunct encodeReqAuthInfo,
                                                                            void * requesterState, HandleCertificateProvisioningResultFunct onCertProvDone)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    IPAddress endPointAddr;

    VerifyOrExit(IPAddress::FromString(WOCAServerAddr, endPointAddr), err = WEAVE_ERROR_INVALID_ADDRESS);

    mReqType = reqType;
    mEncodeReqAuthInfo = encodeReqAuthInfo;
    mReqState = requesterState;
    mOnCertProvDone = onCertProvDone;

    mDoMfrAttest = (reqType == WeaveCertProvEngine::kReqType_GetInitialOpDeviceCert) ? true : false;

    printf("Initiating communication with Certificate Provisioning service");

    printf("DEBUG DEBUG DEBUG 03 WOCAServerAddr = %s\n", WOCAServerAddr);
    printf("DEBUG DEBUG DEBUG 04 WOCAServerEndPointId = %" PRIX64 "\n", WOCAServerEndPointId);

    // Create a binding and begin the process of preparing it for talking to the Certificate Provisioning service.
    mBinding = ExchangeMgr->NewBinding(HandleCertificateProvisioningBindingEvent, this);
    VerifyOrExit(mBinding != NULL, err = WEAVE_ERROR_NO_MEMORY);

    err = mBinding->BeginConfiguration()
            .Target_NodeId(WOCAServerEndPointId)
            .TargetAddress_IP(endPointAddr)
            .Transport_UDP_WRM()
            .Security_None()
            .PrepareBinding();
    // err = mBinding->BeginConfiguration()
    //         .Target_ServiceEndpoint(CertificateProvisioningEndPointId)
    //         .Transport_UDP_WRM()
    //         .Security_SharedCASESession()
    //         .PrepareBinding();
    SuccessOrExit(err);

    err = mCertProvEngine.Init(mBinding, this, this, CertProvClientEventHandler, this);
    SuccessOrExit(err);

exit:
    // if (err != WEAVE_NO_ERROR)
    // {
    //     HandleCertificateProvisioningResult(err, kWeaveProfile_Common, Profiles::Common::kStatus_InternalError);
    // }
    return err;
}

void MockCertificateProvisioningClient::HandleCertificateProvisioningBindingEvent(void *const appState,
                                                                                  const nl::Weave::Binding::EventType event,
                                                                                  const nl::Weave::Binding::InEventParam &inParam,
                                                                                  nl::Weave::Binding::OutEventParam &outParam)
{
    uint32_t statusReportProfileId;
    uint16_t statusReportStatusCode;
    MockCertificateProvisioningClient *client = static_cast<MockCertificateProvisioningClient *>(appState);

    switch (event)
    {
    case Binding::kEvent_BindingReady:
        printf("Certificate Provisioning client binding ready\n");

        client->SendGetCertificateRequest();
        break;

    case Binding::kEvent_PrepareFailed:
        printf("Certificate Provisioning client binding prepare failed: %s\n", nl::ErrorStr(inParam.PrepareFailed.Reason));

        if (inParam.PrepareFailed.StatusReport != NULL)
        {
            statusReportProfileId = inParam.PrepareFailed.StatusReport->mProfileId;
            statusReportStatusCode = inParam.PrepareFailed.StatusReport->mStatusCode;
        }
        else
        {
            statusReportProfileId = kWeaveProfile_Security;
            statusReportStatusCode = Profiles::Security::kStatusCode_ServiceCommunicationError;
        }

        client->HandleCertificateProvisioningResult(inParam.PrepareFailed.Reason,
                statusReportProfileId, statusReportStatusCode);
        break;

    case nl::Weave::Binding::kEvent_BindingFailed:
        printf("Certificate Provisioning client binding failed: %s\n", nl::ErrorStr(inParam.BindingFailed.Reason));

        statusReportProfileId = kWeaveProfile_Security;
        statusReportStatusCode = Profiles::Security::kStatusCode_ServiceCommunicationError;

        client->HandleCertificateProvisioningResult(inParam.BindingFailed.Reason,
                statusReportProfileId, statusReportStatusCode);
        break;

    default:
        Binding::DefaultEventHandler(appState, event, inParam, outParam);
        break;
    }
}

void MockCertificateProvisioningClient::SendGetCertificateRequest(void)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;

    err = mCertProvEngine.Init(mBinding, this, this, CertProvClientEventHandler, this);
    SuccessOrExit(err);

    err = mCertProvEngine.StartCertificateProvisioning(mReqType, mDoMfrAttest);
    SuccessOrExit(err);

    printf("Sending GetCertificateRequest to the Weave Operational Certificate Provisioning (WOCA) Server");

exit:
    if (err != WEAVE_NO_ERROR)
    {
        HandleCertificateProvisioningResult(err, kWeaveProfile_Common, Profiles::Common::kStatus_InternalError);
    }
}

void MockCertificateProvisioningClient::HandleCertificateProvisioningResult(WEAVE_ERROR localErr, uint32_t statusProfileId, uint16_t statusCode)
{
    // Close the binding if necessary.
    if (mBinding != NULL)
    {
        mBinding->Close();
        mBinding = NULL;
    }

    if (localErr != WEAVE_NO_ERROR)
    {
        printf("Certificate Provisioning failed with %s: %s",
                 (localErr == WEAVE_ERROR_STATUS_REPORT_RECEIVED) ? "status report from service" : "local error",
                 (localErr == WEAVE_ERROR_STATUS_REPORT_RECEIVED) ? ::nl::StatusReportStr(statusProfileId, statusCode)
                                                             : ::nl::ErrorStr(localErr));

        // Choose an appropriate StatusReport to return if not already given.
        if (statusProfileId == 0 && statusCode == 0)
        {
            if (localErr == WEAVE_ERROR_TIMEOUT)
            {
                statusProfileId = kWeaveProfile_Security;
                statusCode = Profiles::Security::kStatusCode_ServiceCommunicationError;
            }
            else
            {
                statusProfileId = kWeaveProfile_Common;
                statusCode = Profiles::Common::kStatus_InternalError;
            }
        }
    }

    // CallBack to the Calling Application.
    mOnCertProvDone(mReqState, localErr, statusProfileId, statusCode);
}

// ===== Persisted Operational Device Credentials.

WEAVE_ERROR MockCertificateProvisioningClient::GetDeviceId(uint64_t & deviceId)
{
    deviceId = mDeviceId;

    return WEAVE_NO_ERROR;
}

WEAVE_ERROR MockCertificateProvisioningClient::GetDeviceCertificate(uint8_t *& cert, uint16_t & certLen)
{
    cert = mDeviceCert;
    certLen = mDeviceCertLen;

    return WEAVE_NO_ERROR;
}

WEAVE_ERROR MockCertificateProvisioningClient::GetDeviceIntermediateCACerts(uint8_t *& certs, uint16_t & certsLen)
{
    certs = mDeviceIntermediateCACerts;
    certsLen = mDeviceIntermediateCACertsLen;

    return WEAVE_NO_ERROR;
}

WEAVE_ERROR MockCertificateProvisioningClient::GetDevicePrivateKey(uint8_t *& key, uint16_t & keyLen)
{
    key = mDevicePrivateKey;
    keyLen = mDevicePrivateKeyLen;

    return WEAVE_NO_ERROR;
}

WEAVE_ERROR MockCertificateProvisioningClient::StoreDeviceId(uint64_t deviceId)
{
    mDeviceId = deviceId;

    return WEAVE_NO_ERROR;
}

WEAVE_ERROR MockCertificateProvisioningClient::StoreDeviceCertificate(const uint8_t * cert, uint16_t certLen)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    uint8_t *certCopy = NULL;

    certCopy = (uint8_t *)malloc(certLen);
    VerifyOrExit(certCopy != NULL, err = WEAVE_ERROR_NO_MEMORY);
    memcpy(certCopy, cert, certLen);

    if (mDeviceCert != NULL)
        free(mDeviceCert);

    mDeviceCert = certCopy;
    mDeviceCertLen = certLen;

    // Setup to use operational device certificate in subsequence CASE sessions.
    gCASEOptions.NodeCert = mDeviceCert;
    gCASEOptions.NodeCertLength = mDeviceCertLen;

exit:
    if (err != WEAVE_NO_ERROR && certCopy != NULL)
        free(certCopy);
    return err;
}

WEAVE_ERROR MockCertificateProvisioningClient::StoreDeviceIntermediateCACerts(const uint8_t * certs, uint16_t certsLen)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    uint8_t *certsCopy = NULL;

    certsCopy = (uint8_t *)malloc(certsLen);
    VerifyOrExit(certsCopy != NULL, err = WEAVE_ERROR_NO_MEMORY);
    memcpy(certsCopy, certs, certsLen);

    if (mDeviceIntermediateCACerts != NULL)
        free(mDeviceIntermediateCACerts);

    mDeviceIntermediateCACerts = certsCopy;
    mDeviceIntermediateCACertsLen = certsLen;

    // Setup to use operational device intermediate CA certificates in subsequence CASE sessions.
    gCASEOptions.NodeCert = mDeviceIntermediateCACerts;
    gCASEOptions.NodeCertLength = mDeviceIntermediateCACertsLen;

exit:
    if (err != WEAVE_NO_ERROR && certsCopy != NULL)
        free(certsCopy);
    return err;
}

WEAVE_ERROR MockCertificateProvisioningClient::StoreDevicePrivateKey(const uint8_t * key, uint16_t keyLen)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    uint8_t *keyCopy = NULL;

    keyCopy = (uint8_t *)malloc(keyLen);
    VerifyOrExit(keyCopy != NULL, err = WEAVE_ERROR_NO_MEMORY);
    memcpy(keyCopy, key, keyLen);

    if (mDevicePrivateKey != NULL)
        free(mDevicePrivateKey);

    mDevicePrivateKey = keyCopy;
    mDevicePrivateKeyLen = keyLen;

    // Setup to use operational device private key in subsequence CASE sessions.
    gCASEOptions.NodeCert = mDevicePrivateKey;
    gCASEOptions.NodeCertLength = mDevicePrivateKeyLen;

exit:
    if (err != WEAVE_NO_ERROR && keyCopy != NULL)
        free(keyCopy);
    return err;
}

void MockCertificateProvisioningClient::ClearOperationalDeviceCredentials(void)
{
    mDeviceId = kNodeIdNotSpecified;
    if (mDeviceCert != NULL)
    {
        free(mDeviceCert);
        mDeviceCert = NULL;
    }
    mDeviceCertLen = 0;
    if (mDeviceIntermediateCACerts != NULL)
    {
        free(mDeviceIntermediateCACerts);
        mDeviceIntermediateCACerts = NULL;
    }
    mDeviceIntermediateCACertsLen = 0;
    if (mDevicePrivateKey != NULL)
    {
        free(mDevicePrivateKey);
        mDevicePrivateKey = NULL;
    }
    mDevicePrivateKeyLen = 0;

    gCASEOptions.NodeCert = NULL;
    gCASEOptions.NodeCertLength = 0;
    gCASEOptions.NodeIntermediateCert = NULL;
    gCASEOptions.NodeIntermediateCertLength = 0;
    gCASEOptions.NodePrivateKey = NULL;
    gCASEOptions.NodePrivateKeyLength = 0;
}

WEAVE_ERROR MockCertificateProvisioningClient::GetManufacturerDeviceCertificate(uint8_t *& cert, uint16_t & certLen)
{
    // TODO: Fix it
    cert = mDeviceCert;
    certLen = mDeviceCertLen;

    return WEAVE_NO_ERROR;
}

WEAVE_ERROR MockCertificateProvisioningClient::GetManufacturerDeviceIntermediateCACerts(uint8_t *& certs, uint16_t & certsLen)
{
    certs = NULL;
    certsLen = 0;

    return WEAVE_NO_ERROR;
}

WEAVE_ERROR MockCertificateProvisioningClient::GetManufacturerDevicePrivateKey(uint8_t *& key, uint16_t & keyLen)
{
    // TODO: Fix it
    key = mDevicePrivateKey;
    keyLen = mDevicePrivateKeyLen;

    return WEAVE_NO_ERROR;
}
