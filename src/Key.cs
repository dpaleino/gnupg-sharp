// Key.cs
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
	/// Represents a single key (be it a primary, subkey, ...)
	/// </summary>
	public class Key {
		private RecordType _type;
		private TrustLevel _trust;
		private int _bits;
		private Algorithm _algorithm;
		private string _id;
		private string _creationDate;
		private string _expirationDate;
		private TrustLevel _ownerTrust;
		private ArrayList _uids;
		private ArrayList _uats;
		private string _fingerprint;
		
		/// <summary>
		/// Main constructor.
		/// </summary>
		/// <param name="KeyID">
		/// A <see cref="System.String"/>, the exact key ID (8 or 16 chars,
		/// with or without preceding 0x / 0X).
		/// </param>
		public Key(string KeyID) {
			KeyID = KeyID.Replace("0x", "").Replace("0X", "");
			if ((KeyID.Length != 8) && (KeyID.Length != 16)) {
				throw new GPGException(String.Format("invalid KeyID ({0}) to build Key object.", KeyID));
			}
			
			GPG gpg = new GPG("0x"+KeyID, Commands.List);
			gpg.Exec();
			this._uids = new ArrayList();
			this._uats = new ArrayList();
			ArrayList tmp_uids = new ArrayList();
			ArrayList tmp_uats = new ArrayList();
			bool isMyKey = false;
			
			foreach (string line in gpg.Output.Split('\n')) {
				RecordType tag = Utils.GetRecordType(Utils.GetField(line, 0));
				
				if ((tag == RecordType.PublicKey) || (tag == RecordType.Subkey)) {
					if (Utils.GetField(line, 4).ToUpper().Contains(KeyID.ToUpper())) {
						ParseLine(line);
						UpdateFields();
						isMyKey = true;
					} else {
						isMyKey = false;
					}
				}
				// We have some "data" for our key, grab it.
				// Example data:
				//   uat:u::::2008-01-04::4E2CB61790C019A48949A0124DC9F6CD00AE5E28::1 6727:
				//   uid:u::::2008-01-02::71F3098861D9F69E3C427819AE3F615378EE8009::Hanska <aksnah@gmail.com>:
				//   uid:u::::2006-02-01::64E94BC187C9B38AD5070B2327C4211970D90639::David Paleino <david.paleino@poste.it>:
				//   uid:r::::::6A12CAA95C42D93D4A2AD83E85793C9120BCC585::David Paleino <d.paleino@gnudental.org>:
				//   uid:u::::2007-12-30::9CE39242A56CA074C46D5EB842C0AF1B9493EFFA::David Paleino (Alioth account) <hanska-guest@alioth.debian.org>:
				else if ((tag == RecordType.UserAttribute) || (tag == RecordType.UserId)) {
					if (isMyKey) {
						if (tag == RecordType.UserId) {
							tmp_uids.Add(Utils.GetField(line, 7));
						} else if (tag == RecordType.UserAttribute) {
							tmp_uats.Add(Utils.GetField(line, 7));
						}
					}
				}
			}
			
			
			foreach (string hash in tmp_uids) {
				this._uids.Add(new UID(KeyID, hash, RecordType.UserId));
			}
			foreach (string hash in tmp_uats) {
				this._uats.Add(new UID(KeyID, hash, RecordType.UserAttribute));
			}
		}
		
		/// <summary>
		/// Stores the fields from the given line into appropriate variables.
		/// </summary>
		/// <param name="line">
		/// A <see cref="System.String"/>
		/// </param>
		private void ParseLine(string line) {
			// This is the format we receive:
			//   pub:u:1024:17:E6AA90171392B174:1138786427:::u:::scaESCA:
			//   sub:u:4096:1:BB45ABF7A71D5481:1203325654::::::e:
			
			this._type = Utils.GetRecordType(Utils.GetField(line, 0));
			this._trust = Utils.GetTrustLevel(Utils.GetField(line, 1));
			this._bits = Convert.ToInt32(Utils.GetField(line, 2));
			this._algorithm = Utils.GetAlgorithm(Convert.ToInt32(Utils.GetField(line, 3)));
			this._id = Utils.GetField(line, 4);
			// FIXME: with --fixed-list-mode, the dates are given as seconds
			//        from Epoch: these are not recognized by Convert.ToDateTime()
			this._creationDate = Utils.GetField(line, 5);
			this._expirationDate = Utils.GetField(line, 6);
			if (this._type == RecordType.PublicKey) {
				this._ownerTrust = Utils.GetTrustLevel(Utils.GetField(line, 8));
			}
			// TODO: try to parse also the usage flags (scaESCA and e above)
		}
		
		/// <summary>
		/// Updates other fields, not present in /^pub/ or /^sub/ lines.
		/// </summary>
		private void UpdateFields() {
			this._fingerprint = GetFingerprint(this.ID);
		}
		
		/// <summary>
		/// Get the Fingerprint for the specified key.
		/// </summary>
		/// <param name="KeyID">
		/// A <see cref="System.String"/>, the Key ID to work on.
		/// </param>
		/// <returns>
		/// A <see cref="System.String"/>, the Fingerprint of the specified Key.
		/// </returns>
		public static string GetFingerprint (string KeyID) {
			// The fingerprint is returned in the form:
			//   fpr:::::::::2BABC6254E66E7B8450AC3E1E6AA90171392B174:
			GPG gpg = new GPG(KeyID, Commands.List);
			gpg.Exec();
			bool isMyKey = false;
			foreach (string line in gpg.Output.Split('\n')) {
				RecordType tag = Utils.GetRecordType(Utils.GetField(line, 0));
				if (
				    (tag == RecordType.PublicKey) ||
				    (tag == RecordType.Subkey)
				   ) {
					if (Utils.GetField(line, 4).Contains(KeyID.ToUpper())) {
						// It is our key.
						isMyKey = true;
					} else {
						isMyKey = false;
					}
				} else {
					if (isMyKey && (tag == RecordType.Fingerprint)) {
						return Utils.GetField(line, 9);
					}
				}
			}
			throw new GPGException(gpg.Error);
		}
		
		/// <value>
		/// The Key type (Public Key, Subkey, ...)
		/// </value>
		public RecordType KeyType {
			get {
				return this._type;
			}
		}
		
		/// <value>
		/// The Trust level
		/// </value>
		public TrustLevel Trust {
			get {
				return this._trust;
			}
		}
		
		/// <value>
		/// The number of bits
		/// </value>
		public int Bits {
			get {
				return this._bits;
			}
		}
		
		/// <value>
		/// The Key algorithm (DSA, RSA, Elgamal, ...)
		/// </value>
		public Algorithm KeyAlgorithm {
			get {
				return this._algorithm;
			}
		}
		
		/// <value>
		/// The Key ID
		/// </value>
		public string ID {
			get {
				return this._id;
			}
		}
		
		/// <value>
		/// The creation date
		/// </value>
		public string CreationDate {
			get {
				return this._creationDate;
			}
		}
		
		/// <value>
		/// The expiration date
		/// </value>
		public string ExpirationDate {
			get {
				return this._expirationDate;
			}
		}
		
		/// <value>
		/// The owner trust level. Only for <see cref="RecordType.PublicKey"/>.
		/// </value>
		public TrustLevel OwnerTrust {
			get {
				return this._ownerTrust;
			}
		}
		
		/// <value>
		/// The fingerprint.
		/// </value>
		public string Fingerprint {
			get {
				return this._fingerprint;
			}
		}
		
		/// <value>
		/// Associated User Identities.
		/// </value>
		public ArrayList UIDs {
			get {
				return this._uids;
			}
		}
		
		/// <value>
		/// Associated User Attributes.
		/// </value>
		public ArrayList UATs {
			get {
				return this._uats;
			}
		}
	}
}
