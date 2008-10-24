// Signature.cs
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

namespace GnuPG {
	/// <summary>
	/// Represents a signature on a UID/UAT
	/// </summary>
	public class Signature {
		private Algorithm _algorithm;
		private string _signingKey;
		private string _signingDate;
		private Hashtable _user;
		
		/// <summary>
		/// Main constructor.
		/// </summary>
		/// <param name="KeyID">
		/// A <see cref="System.String"/>, the primary key ID.
		/// </param>
		/// <param name="SignKey">
		/// A <see cref="System.String"/>, the signing key ID.
		/// </param>
		/// <param name="SignDate">
		/// A <see cref="System.String"/>, the signature date (seconds from Epoch)
		/// </param>
		public Signature(string KeyID, string SignKey, string SignDate) {
			// sig:::17:F4B4B0CC797EBFAB:1223678701::::Enrico Zini <enrico@enricozini.com>:10x:
//			Console.WriteLine(String.Format("Key: {0} - SignKey: {1} - SignDate: {2}", KeyID, Key, Date));
			GPG gpg = new GPG(KeyID, Commands.List);
			gpg.Exec();
			foreach (string line in gpg.Output.Split('\n')) {
				RecordType tag = Utils.GetRecordType(Utils.GetField(line, 0));
				if (tag == RecordType.Signature) {
					string key = Utils.GetField(line, 4);
					string date = Utils.GetField(line, 5);
					if ((key == SignKey) && (date == SignDate)) {
						this._algorithm = Utils.GetAlgorithm(Convert.ToInt32(Utils.GetField(line, 3)));
						this._user = Utils.ParseUsername(Utils.GetField(line, 9));
						this._signingKey = SignKey;
						this._signingDate = SignDate;
						// TODO: also parse the "10x" above? The docs give very poor info:
						/*
						 * 11. Field:  Signature class.  This is a 2 digit hexnumber followed by
						 *             either the letter 'x' for an exportable signature or the
						 *             letter 'l' for a local-only signature.
						 *             The class byte of an revocation key is also given here,
						 *             'x' and 'l' ist used the same way.
						 */
					}
				}
			}
		}
		
		/// <value>
		/// The signature algorithm
		/// </value>
		public Algorithm Algorithm {
			get {
				return this._algorithm;
			}
		}
		
		/// <value>
		/// The name of the signing user
		/// </value>
		public string Name {
			get {
				return this._user["name"].ToString();
			}
		}
		
		/// <value>
		/// The comment of the signing user
		/// </value>
		public string Comment {
			get {
				return this._user["comment"].ToString();
			}
		}
		
		/// <value>
		/// The e-mail address of the signing user
		/// </value>
		public string Email {
			get {
				return this._user["email"].ToString();
			}
		}
		
		/// <value>
		/// The signing key.
		/// </value>
		public string SigningKey {
			get {
				return this._signingKey;
			}
		}
		
		/// <value>
		/// The signature date (seconds from Epoch)
		/// </value>
		public string SigningDate {
			get {
				return this._signingDate;
			}
		}
	}
}
