// Utils.cs
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
using System.Collections;
using System.Text.RegularExpressions;

namespace GnuPG {
	internal static class Utils {
		/// <summary>
		/// Gives the specified field as a <see cref="System.String"/>
		/// </summary>
		/// <param name="Line">
		/// A <see cref="System.String"/>, the line obtained with --with-colons.
		/// </param>
		/// <param name="Field">
		/// A <see cref="System.Int32"/>, the field position (first field is 0).
		/// </param>
		/// <returns>
		/// A <see cref="System.String"/>, the specified field.
		/// </returns>
		internal static string GetField(string Line, int Field) {
			if (Line != "") {
				string[] output = Line.Split(':');
				return output[Field];
			}
			return "";
		}
		
		/// <summary>
		/// Gives a string[] containing the fields.
		/// </summary>
		/// <param name="Line">
		/// A <see cref="System.String"/>, the line obtained with --with-colons.
		/// </param>
		/// <returns>
		/// An array of <see cref="System.String"/>, containing all the fields.
		/// </returns>
		internal static string[] GetField(string Line) {
			if (Line != "") {
				return Line.Split(':');
			}
			return new string[] {};
		}
		
		/// <summary>
		/// Translate a Tag from output obtained with --with-colons into a 
		/// RecordType field.
		/// </summary>
		/// <param name="Tag">
		/// A <see cref="System.String"/>
		/// </param>
		/// <returns>
		/// A <see cref="RecordType"/>
		/// </returns>
		internal static RecordType GetRecordType(string Tag) {
			switch (Tag) {
				case "pub":
					return RecordType.PublicKey;
				case "crt":
					return RecordType.X509Certificate;
				case "crs":
					return RecordType.X509CertificatePrivate;
				case "sub":
					return RecordType.Subkey;
				case "sec":
					return RecordType.SecretKey;
				case "ssb":
					return RecordType.SecretSubkey;
				case "uid":
					return RecordType.UserId;
				case "uat":
					return RecordType.UserAttribute;
				case "sig":
					return RecordType.Signature;
				case "rev":
					return RecordType.RevocationSignature;
				case "fpr":
					return RecordType.Fingerprint;
				case "pkd":
					return RecordType.PublicKeyData;
				case "grp":
					return RecordType.Group;
				case "rvk":
					return RecordType.RevocationKey;
				case "tru":
					return RecordType.TrustDatabaseInformation;
				case "spk":
					return RecordType.SignatureSubpacket;
				default:
					return RecordType.Unknown;
			}
		}
		
		/// <summary>
		/// Translate a trust field from output obtained with --with-colons into
		/// a TrustLevel field. 
		/// </summary>
		/// <param name="Tag">
		/// A <see cref="System.String"/>
		/// </param>
		/// <returns>
		/// A <see cref="TrustLevel"/>
		/// </returns>
		internal static TrustLevel GetTrustLevel(string Tag) {
			switch (Tag) {
				case "o":
					return TrustLevel.UnknownNew;
				case "i":
					return TrustLevel.Invalid;
				case "d":
					return TrustLevel.Disabled;
				case "r":
					return TrustLevel.Revoked;
				case "e":
					return TrustLevel.Expired;
				case "q":
					return TrustLevel.Undefined;
				case "n":
					return TrustLevel.Never;
				case "m":
					return TrustLevel.Marginal;
				case "f":
					return TrustLevel.Full;
				case "u":
					return TrustLevel.Ultimate;
				case "-":
				default:
					return TrustLevel.Unknown;
			}
		}
		
		/// <summary>
		/// Translate an algorithm field from output obtained with --with-colons
		/// into an Algorithm field. 
		/// </summary>
		/// <param name="Tag">
		/// A <see cref="System.Int32"/>
		/// </param>
		/// <returns>
		/// A <see cref="Algorithm"/>
		/// </returns>
		internal static Algorithm GetAlgorithm(int Tag) {
			switch (Tag) {
				case 1:
					return Algorithm.RSA;
				case 2:
					return Algorithm.RSAEncryptOnly;
				case 3:
					return Algorithm.RSASignOnly;
				case 16:
					return Algorithm.ElgamalEncryptOnly;
				case 17:
					return Algorithm.DSA;
				case 20:
					return Algorithm.ElgamalSignAndEncrypt;
				default:
					return Algorithm.Unknown;
			}
		}
		
		internal static Hashtable ParseUsername(string Username) {
			Hashtable hash = new Hashtable();
			string u = Username; // just for convenience
			Regex re = new Regex(Defines.UIDRegex);
			if (re.IsMatch(u)) {
				Match m = re.Match(u);
				hash.Add("name", m.Groups[1].Value.Trim());
				hash.Add("comment", m.Groups[3].Value.Trim());
				hash.Add("email", m.Groups[4].Value.Trim());
			}
			else {
				throw new GPGException("Cannot parse username.");
			}
			return hash;
		}
	}
}
