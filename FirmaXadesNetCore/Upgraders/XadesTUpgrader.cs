// --------------------------------------------------------------------------------------------------------------------
// XadesTUpgrader.cs
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

using FirmaXadesNetCore.Signature;
using FirmaXadesNetCore.Upgraders.Parameters;
using FirmaXadesNetCore.Utils;
using Microsoft.Xades;
using System;
using System.Collections;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;

namespace FirmaXadesNetCore.Upgraders
{
    class XadesTUpgrader : IXadesUpgrader
    {
        #region Public methods

        public void Upgrade(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            var unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;

            try
            {
                if (unsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Count > 0)
                {
                    throw new Exception("La firma ya contiene un sello de tiempo");
                }

                var excTransform = new XmlDsigExcC14NTransform();

                var signatureValueElementXpaths = new ArrayList
                {
                    "ds:SignatureValue"
                };

                var signatureValueHash = DigestUtil.ComputeHashValue(
                    XMLUtil.ComputeValueOfElementList(signatureDocument.XadesSignature, signatureValueElementXpaths,
                        excTransform), parameters.DigestMethod);

                var tsa = parameters.TimeStampClient.GetTimeStamp(signatureValueHash, parameters.DigestMethod, true);

                var signatureTimeStamp = new TimeStamp("SignatureTimeStamp")
                {
                    Id = "SignatureTimeStamp-" + signatureDocument.XadesSignature.Signature.Id,
                    CanonicalizationMethod = new CanonicalizationMethod
                    {
                        Algorithm = excTransform.Algorithm
                    },
                    EncapsulatedTimeStamp =
                    {
                        PkiData = tsa,
                        Id = "SignatureTimeStamp-" + Guid.NewGuid()
                    }
                };

                unsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Add(signatureTimeStamp);

                signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;

                signatureDocument.UpdateDocument();
            }
            catch (Exception ex)
            {
                throw new Exception("Ha ocurrido un error al insertar el sellado de tiempo.", ex);
            }
        }

        #endregion
    }
}