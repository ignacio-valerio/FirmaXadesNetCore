// --------------------------------------------------------------------------------------------------------------------
// XadesXLUpgrader.cs
//
// FirmaXadesNet - Librería para la generación de firmas XADES
// Copyright (C) 2016 Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
//
// This program is free software: you can redistribute it and/or modify
// it under the +terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/. 
//
// E-Mail: informatica@gemuc.es
// 
// --------------------------------------------------------------------------------------------------------------------

using FirmaXadesNetCore.Clients;
using FirmaXadesNetCore.Signature;
using FirmaXadesNetCore.Upgraders.Parameters;
using FirmaXadesNetCore.Utils;
using Microsoft.Xades;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;
using System.Xml;

namespace FirmaXadesNetCore.Upgraders
{
    class XadesXLUpgrader : IXadesUpgrader
    {
        #region Public methods

        public void Upgrade(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            var signingCertificate = signatureDocument.XadesSignature.GetSigningCertificate();

            var unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;

            unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs = new CompleteCertificateRefs
            {
                Id = "CompleteCertificates-" + Guid.NewGuid()
            };

            unsignedProperties.UnsignedSignatureProperties.CertificateValues = new CertificateValues();

            var certificateValues = unsignedProperties.UnsignedSignatureProperties.CertificateValues;

            certificateValues.Id = "CertificatesValues-" + Guid.NewGuid();

            unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs = new CompleteRevocationRefs
            {
                Id = "CompleteRev-" + Guid.NewGuid()
            };

            unsignedProperties.UnsignedSignatureProperties.RevocationValues = new RevocationValues
            {
                Id = "RevocationValues-" + Guid.NewGuid()
            };

            _ = AddCertificate(signingCertificate, unsignedProperties, false, parameters.OCSPServers, parameters.CRL,
                parameters.DigestMethod, parameters.GetOcspUrlFromCertificate);

            _ = AddTSACertificates(unsignedProperties, parameters.OCSPServers, parameters.CRL,
                parameters.DigestMethod, parameters.GetOcspUrlFromCertificate);

            signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;

            TimeStampCertRefs(signatureDocument, parameters);

            signatureDocument.UpdateDocument();
        }

        #endregion

        #region Private methods

        private string GetResponderName(ResponderID responderId, ref bool byKey)
        {
            var dt = (DerTaggedObject)responderId.ToAsn1Object();

            if (dt.TagNo == 1)
            {
                byKey = false;

                return new X500DistinguishedName(dt.GetObject().GetEncoded()).Name;
            }

            if (dt.TagNo != 2)
            {
                return null;
            }

            var tagger = (Asn1TaggedObject)responderId.ToAsn1Object();

            var pubInfo = (Asn1OctetString)tagger.GetObject();

            byKey = true;

            return Convert.ToBase64String(pubInfo.GetOctets());
        }

        /// <summary>
        /// Comprueba si dos DN son equivalentes
        /// </summary>
        /// <param name="dn"></param>
        /// <param name="other"></param>
        /// <returns></returns>
        private bool EquivalentDN(X500DistinguishedName dn, X500DistinguishedName other)
        {
            return X509Name.GetInstance(Asn1Object.FromByteArray(dn.RawData))
                .Equivalent(X509Name.GetInstance(Asn1Object.FromByteArray(other.RawData)));
        }

        /// <summary>
        /// Determina si un certificado ya ha sido añadido a la colección de certificados
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="unsignedProperties"></param>
        /// <returns></returns>
        private bool CertificateChecked(X509Certificate2 cert, UnsignedProperties unsignedProperties)
        {
            return (from EncapsulatedX509Certificate item in unsignedProperties.UnsignedSignatureProperties
                    .CertificateValues.EncapsulatedX509CertificateCollection
                select new X509Certificate2(item.PkiData)).Any(certItem => certItem.Thumbprint == cert.Thumbprint);
        }

        /// <summary>
        /// Inserta en la lista de certificados el certificado y comprueba la valided del certificado.
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="unsignedProperties"></param>
        /// <param name="addCertValue"></param>
        /// <param name="extraCerts"></param>
        private async Task AddCertificate(X509Certificate2 cert, UnsignedProperties unsignedProperties, bool addCert,
            IEnumerable<OcspServer> ocspServers,
            IEnumerable<X509Crl> crlList, FirmaXadesNetCore.Crypto.DigestMethod digestMethod,
            bool addCertificateOcspUrl, X509Certificate2[] extraCerts = null)
        {
            if (addCert)
            {
                if (CertificateChecked(cert, unsignedProperties))
                {
                    return;
                }

                var guidCert = Guid.NewGuid().ToString();

                var chainCert = new Cert
                {
                    IssuerSerial =
                    {
                        X509IssuerName = cert.IssuerName.Name,
                        X509SerialNumber = cert.GetSerialNumberAsDecimalString()
                    }
                };

                DigestUtil.SetCertDigest(cert.GetRawCertData(), digestMethod, chainCert.CertDigest);

                chainCert.URI = "#Cert" + guidCert;

                unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs.CertRefs.CertCollection
                    .Add(chainCert);

                var encapsulatedX509Certificate = new EncapsulatedX509Certificate
                {
                    Id = "Cert" + guidCert,
                    PkiData = cert.GetRawCertData()
                };

                unsignedProperties.UnsignedSignatureProperties.CertificateValues.EncapsulatedX509CertificateCollection
                    .Add(encapsulatedX509Certificate);
            }

            var chain = CertUtil.GetCertChain(cert, extraCerts).ChainElements;

            if (chain.Count > 1)
            {
                var enumerator = chain.GetEnumerator();

                enumerator.MoveNext();

                enumerator.MoveNext();

                var valid = ValidateCertificateByCRL(unsignedProperties, cert, enumerator.Current.Certificate, crlList,
                    digestMethod);

                if (!valid)
                {
                    var ocspCerts = await ValidateCertificateByOCSP(unsignedProperties, cert,
                        enumerator.Current.Certificate, ocspServers, digestMethod, addCertificateOcspUrl);

                    if (ocspCerts != null)
                    {
                        var startOcspCert = DetermineStartCert(ocspCerts);

                        if (!EquivalentDN(startOcspCert.IssuerName, enumerator.Current.Certificate.SubjectName))
                        {
                            var chainOcsp = CertUtil.GetCertChain(startOcspCert, ocspCerts);

                            _ = AddCertificate(chainOcsp.ChainElements[1].Certificate, unsignedProperties, true,
                                ocspServers, crlList, digestMethod, addCertificateOcspUrl, ocspCerts);
                        }
                    }
                }

                _ = AddCertificate(enumerator.Current.Certificate, unsignedProperties, true, ocspServers, crlList,
                    digestMethod, addCertificateOcspUrl, extraCerts);
            }
        }

        private bool ExistsCRL(CRLRefCollection collection, string issuer)
        {
            return collection.Cast<CRLRef>().Any(crlRef => crlRef.CRLIdentifier.Issuer == issuer);
        }

        private long? GetCRLNumber(X509Crl crlEntry)
        {
            var extValue = crlEntry.GetExtensionValue(X509Extensions.CrlNumber);

            if (extValue == null)
            {
                return null;
            }

            var asn1Value = X509ExtensionUtilities.FromExtensionValue(extValue);

            return DerInteger.GetInstance(asn1Value).PositiveValue.LongValue;
        }

        private bool ValidateCertificateByCRL(UnsignedProperties unsignedProperties, X509Certificate2 certificate,
            X509Certificate2 issuer,
            IEnumerable<X509Crl> crlList, FirmaXadesNetCore.Crypto.DigestMethod digestMethod)
        {
            var clientCert = certificate.ToBouncyX509Certificate();
            var issuerCert = issuer.ToBouncyX509Certificate();

            foreach (var crlEntry in crlList)
            {
                if (!crlEntry.IssuerDN.Equivalent(issuerCert.SubjectDN) ||
                    crlEntry.NextUpdate.Value <= DateTime.Now)
                {
                    continue;
                }

                if (crlEntry.IsRevoked(clientCert))
                {
                    throw new Exception("Certificado revocado");
                }

                if (ExistsCRL(unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.CRLRefs
                        .CRLRefCollection, issuer.Subject))
                {
                    return true;
                }

                var idCrlValue = "CRLValue-" + Guid.NewGuid().ToString();

                var crlRef = new CRLRef
                {
                    CRLIdentifier =
                    {
                        UriAttribute = "#" + idCrlValue,
                        Issuer = issuer.Subject,
                        IssueTime = crlEntry.ThisUpdate.ToLocalTime()
                    }
                };

                var crlNumber = GetCRLNumber(crlEntry);

                if (crlNumber.HasValue)
                {
                    crlRef.CRLIdentifier.Number = crlNumber.Value;
                }

                var crlEncoded = crlEntry.GetEncoded();

                DigestUtil.SetCertDigest(crlEncoded, digestMethod, crlRef.CertDigest);

                var crlValue = new CRLValue
                {
                    PkiData = crlEncoded,
                    Id = idCrlValue
                };

                unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.CRLRefs
                    .CRLRefCollection.Add(crlRef);

                unsignedProperties.UnsignedSignatureProperties.RevocationValues.CRLValues.CRLValueCollection
                    .Add(crlValue);

                return true;
            }

            return false;
        }

        private async Task<X509Certificate2[]> ValidateCertificateByOCSP(UnsignedProperties unsignedProperties,
            X509Certificate2 client, X509Certificate2 issuer,
            IEnumerable<OcspServer> ocspServers, FirmaXadesNetCore.Crypto.DigestMethod digestMethod,
            bool addCertificateOcspUrl)
        {
            var byKey = false;

            var finalOcspServers = new List<OcspServer>();

            var clientCert = client.ToBouncyX509Certificate();

            var issuerCert = issuer.ToBouncyX509Certificate();

            var ocsp = new OcspClient();

            if (addCertificateOcspUrl)
            {
                var certOcspUrl = ocsp.GetAuthorityInformationAccessOcspUrl(issuerCert);

                if (!string.IsNullOrEmpty(certOcspUrl))
                {
                    finalOcspServers.Add(new OcspServer(certOcspUrl));
                }
            }

            finalOcspServers.AddRange(ocspServers);

            foreach (var ocspServer in finalOcspServers)
            {
                var resp = await ocsp.QueryBinary(clientCert, issuerCert, ocspServer.Url, ocspServer.RequestorName,
                    ocspServer.SignCertificate);

                var status = ocsp.ProcessOcspResponse(resp);

                if (status == Clients.CertificateStatus.Revoked)
                {
                    throw new Exception("Certificado revocado");
                }

                if (status != Clients.CertificateStatus.Good)
                {
                    continue;
                }

                var r = new OcspResp(resp);
                var rEncoded = r.GetEncoded();
                var or = (BasicOcspResp)r.GetResponseObject();

                var guidOcsp = Guid.NewGuid().ToString();

                var ocspRef = new OCSPRef
                {
                    OCSPIdentifier =
                    {
                        UriAttribute = "#OcspValue" + guidOcsp
                    }
                };

                DigestUtil.SetCertDigest(rEncoded, digestMethod, ocspRef.CertDigest);

                var rpId = or.ResponderId.ToAsn1Object();

                ocspRef.OCSPIdentifier.ResponderID = GetResponderName(rpId, ref byKey);

                ocspRef.OCSPIdentifier.ByKey = byKey;

                ocspRef.OCSPIdentifier.ProducedAt = or.ProducedAt.ToLocalTime();

                unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.OCSPRefs.OCSPRefCollection
                    .Add(ocspRef);

                var ocspValue = new OCSPValue
                {
                    PkiData = rEncoded,
                    Id = "OcspValue" + guidOcsp
                };

                unsignedProperties.UnsignedSignatureProperties.RevocationValues.OCSPValues.OCSPValueCollection.Add(
                    ocspValue);

                return (from cert in or.GetCerts()
                    select new X509Certificate2(cert.GetEncoded())).ToArray();
            }

            throw new Exception("El certificado no ha podido ser validado");
        }

        private X509Certificate2 DetermineStartCert(X509Certificate2[] certs)
        {
            X509Certificate2 currentCert = null;

            var isIssuer = true;

            for (var i = 0; i < certs.Length && isIssuer; i++)
            {
                currentCert = certs[i];

                isIssuer = certs.Any(t => EquivalentDN(t.IssuerName, currentCert.SubjectName));
            }

            return currentCert;
        }

        /// <summary>
        /// Inserta y valida los certificados del servidor de sellado de tiempo.
        /// </summary>
        /// <param name="unsignedProperties"></param>
        private async Task AddTSACertificates(UnsignedProperties unsignedProperties,
            IEnumerable<OcspServer> ocspServers,
            IEnumerable<X509Crl> crlList, FirmaXadesNetCore.Crypto.DigestMethod digestMethod,
            bool addCertificateOcspUrl)
        {
            var token = new TimeStampToken(new CmsSignedData(unsignedProperties.UnsignedSignatureProperties
                .SignatureTimeStampCollection[0].EncapsulatedTimeStamp.PkiData));

            var store = token.GetCertificates();

            var tsaCerts = store.EnumerateMatches(null)
                .Select(tsaCert => new X509Certificate2(tsaCert.GetEncoded()))
                .ToList();

            var startCert = DetermineStartCert(tsaCerts.ToArray());

            await AddCertificate(startCert, unsignedProperties, true, ocspServers, crlList, digestMethod,
                addCertificateOcspUrl, tsaCerts.ToArray());
        }

        private void TimeStampCertRefs(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            var nodoFirma = signatureDocument.XadesSignature.GetSignatureElement();

            var nm = new XmlNamespaceManager(signatureDocument.Document.NameTable);
            nm.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);
            nm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            var xmlCompleteCertRefs = nodoFirma.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs",
                nm);

            if (xmlCompleteCertRefs == null)
            {
                signatureDocument.UpdateDocument();
            }

            var signatureValueElementXpaths = new ArrayList
            {
                "ds:SignatureValue",
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp",
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs",
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteRevocationRefs"
            };

            var signatureValueHash = DigestUtil.ComputeHashValue(
                XMLUtil.ComputeValueOfElementList(signatureDocument.XadesSignature, signatureValueElementXpaths),
                parameters.DigestMethod);

            var tsa = parameters.TimeStampClient.GetTimeStamp(signatureValueHash, parameters.DigestMethod, true);

            var xadesXTimeStamp = new TimeStamp("SigAndRefsTimeStamp")
            {
                Id = "SigAndRefsStamp-" + signatureDocument.XadesSignature.Signature.Id,
                EncapsulatedTimeStamp =
                {
                    PkiData = tsa,
                    Id = "SigAndRefsStamp-" + Guid.NewGuid()
                }
            };

            var unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;

            unsignedProperties.UnsignedSignatureProperties.RefsOnlyTimeStampFlag = false;

            unsignedProperties.UnsignedSignatureProperties.SigAndRefsTimeStampCollection.Add(xadesXTimeStamp);

            signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;
        }

        #endregion
    }
}