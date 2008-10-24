// RecordType.cs
// 
// Copyright © 2008 David Paleino <d.paleino@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

using System;

namespace GnuPG {
	/// <summary>
	/// Type of record used by --with-colons
	/// </summary>
	public enum RecordType {
		/// <summary>
		/// Public key
		/// </summary>
		PublicKey,
		/// <summary>
		/// X.509 certificate
		/// </summary>
		X509Certificate,
		/// <summary>
		/// X.509 certificate and private key available
		/// </summary>
		X509CertificatePrivate,
		/// <summary>
		/// Subkey (secondary key)
		/// </summary>
		Subkey,
		/// <summary>
		/// Secret key
		/// </summary>
		SecretKey,
		/// <summary>
		/// Secret subkey (secondary key)
		/// </summary>
		SecretSubkey,
		/// <summary>
		/// User ID (only field 10 is used)
		/// </summary>
		UserId,
		/// <summary>
		/// User attribute (same as user id except for field 10)
		/// </summary>
		UserAttribute,
		/// <summary>
		/// Signature
		/// </summary>
		Signature,
		/// <summary>
		/// Revocation signature
		/// </summary>
		RevocationSignature,
		/// <summary>
		/// Fingerprint (field 10)
		/// </summary>
		Fingerprint,
		/// <summary>
		/// Special field format, see below.
		/// </summary>
		/// <para>If field 1 has the tag "pkd", a listing looks like this:</para>
		/// <code>pkd:0:1024:B665B1435F4C2 .... FF26ABB:</code>
		/// <list>
		/// <item>0 is the index (eg. DSA goes from 0 to 3: p,q,g,y)</item>
		/// <item>1024 is the number of bits in the value</item>
		/// <item>B665B1435F4C2 .... FF26ABB is the value itself</item>
		/// </list>
		PublicKeyData,
		/// <summary>
		/// Reserved for gpgsm
		/// </summary>
		Group,
		/// <summary>
		/// Revocation key
		/// </summary>
		RevocationKey,
		/// <summary>
		/// Trust Database Information
		/// </summary>
		TrustDatabaseInformation,
		/// <summary>
		/// Signature subpacket
		/// </summary>
		SignatureSubpacket,
		/// <summary>
		/// Default fallback type
		/// </summary>
		Unknown
	}
}
