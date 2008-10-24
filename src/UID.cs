// UID.cs
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
	/// Represents a UID/UAT.
	/// </summary>
	public class UID {
//		private ArrayList _sigs;
		private TrustLevel _trust;
		private RecordType _type;
		private string _creationDate;
		private string _expirationDate;
		private string _hash;
		private string _name = "";
		private string _comment = "";
		private string _email = "";
		private string _keyid = "";
		
		/// <summary>
		/// Main constructor.
		/// </summary>
		/// <param name="KeyID">
		/// A <see cref="System.String"/>, the parent key ID.
		/// </param>
		/// <param name="Hash">
		/// A <see cref="System.String"/>, an unique identifier provided by gpg.
		/// </param>
		/// <param name="Type">
		/// A <see cref="RecordType"/>, RecordType.UserId or RecordType.UserAttribute
		/// are the only two currently supported.
		/// </param>
		public UID(string KeyID, string Hash, RecordType Type) {
			this._keyid = KeyID;
			// TODO: Disabled: far too slow:
			//         Keyset foreach: 00:00:13.6448860
			//       while, without:
			//         Keyset foreach: 00:00:03.9610520
//			this._sigs = GetSignatures(KeyID, Hash);
			GPG gpg = new GPG(KeyID, Commands.List);
			gpg.Exec();
			foreach (string line in gpg.Output.Split('\n')) {
				RecordType tag = Utils.GetRecordType(Utils.GetField(line, 0));
				
				// if it's what we're looking for...
				if (tag == Type) {
					// the hashes match...
					string hash = Utils.GetField(line, 7);
					if (hash.ToUpper() == Hash.ToUpper()) {
						ParseLine(line);
					}
				}
			}
		}
		
		/// <summary>
		/// Parses a line of the format:
		/// <code>uid:u::::1138787426::64E94BC187C9B38AD5070B2327C4211970D90639::David Paleino &lt;david.paleino@poste.it&gt;:</code>
		/// and updates its fields.
		/// </summary>
		/// <param name="Line">
		/// A <see cref="System.String"/>
		/// </param>
		public void ParseLine(string Line) {
			this._type = Utils.GetRecordType(Utils.GetField(Line, 0));
			this._trust = Utils.GetTrustLevel(Utils.GetField(Line, 1));
			
			// TODO: these fields are seconds from the Epoch, Convert.ToDateTime()
			//       doesn't recognize them.
			this._creationDate = Utils.GetField(Line, 5);
			this._expirationDate = Utils.GetField(Line, 6);
			this._hash = Utils.GetField(Line, 7);
			
			// these are UID-specific (i.e. not UAT)
			if (this.Type == RecordType.UserId) {
				Hashtable tbl = Utils.ParseUsername(Utils.GetField(Line, 9)); 
				this._name = tbl["name"].ToString();
				this._comment = tbl["comment"].ToString();
				this._email = tbl["email"].ToString();
			} else {
				// TODO: parse Utils.GetField(Line, 9) for UAT.
				// TODO: get the image saved in UAT (or any other data it might
				//       contain).
				/*
				 * Format of the "--attribute-fd" output
				 * =====================================
				 * 
				 * When --attribute-fd is set, during key listings (--list-keys,
				 * --list-secret-keys) GnuPG dumps each attribute packet to the file
				 * descriptor specified.  --attribute-fd is intended for use with
				 * --status-fd as part of the required information is carried on the
				 * ATTRIBUTE status tag (see above).
				 *
				 * The contents of the attribute data is specified by 2440bis, but for
				 * convenience, here is the Photo ID format, as it is currently the only
				 * attribute defined:
				 * 
				 *   Byte 0-1:  The length of the image header.  Due to a historical
				 *              accident (i.e. oops!) back in the NAI PGP days, this is
				 *              a little-endian number.  Currently 16 (0x10 0x00). 
				 *   Byte 2:    The image header version.  Currently 0x01.
				 *   Byte 3:    Encoding format.  0x01 == JPEG.
				 *   Byte 4-15: Reserved, and currently unused.
				 * 
				 * All other data after this header is raw image (JPEG) data.
				 */
			}
		}
		
		/// <summary>
		/// Get signatures on the specified UID/UAT
		/// </summary>
		/// <param name="KeyID">
		/// A <see cref="System.String"/>, the primary Key ID.
		/// </param>
		/// <param name="UIDHash">
		/// A <see cref="System.String"/>, the hash of this UID. See
		/// <see cref="GnuPG.UID.Hash"/>.
		/// </param>
		/// <returns>
		/// A <see cref="ArrayList"/> of <see cref="GnuPG.Signature"/> objects.
		/// </returns>
		public static ArrayList GetSignatures(string KeyID, string UIDHash) {
			ArrayList sigs = new ArrayList();
			GPG gpg = new GPG(KeyID, Commands.List);
			gpg.Exec();
			bool isMyUid = false;
			foreach (string line in gpg.Output.Split('\n')) {
				RecordType tag = Utils.GetRecordType(Utils.GetField(line, 0));
				
				// let's look for our UID.
				if (
				    (tag == RecordType.UserAttribute) ||
				    (tag == RecordType.UserId)
				   ) {
					// the hashes match...
					string hash = Utils.GetField(line, 7);
					if (hash.ToUpper() == UIDHash.ToUpper()) {
						isMyUid = true;
					} else {
						isMyUid = false;
					}
				}
				// we are looking for signatures...
				else if (tag == RecordType.Signature) {
					if (isMyUid) {
						string signKey = Utils.GetField(line, 4);
						string signDate = Utils.GetField(line, 5);
						sigs.Add(new Signature(KeyID, signKey, signDate));
					}
				}
			}
			return sigs;
		}
		
		/// <value>
		/// The ID type... UID/UAT.
		/// </value>
		public RecordType Type {
			get {
				return this._type;
			}
		}
		
		/// <value>
		/// The Trust level.
		/// </value>
		public TrustLevel Trust {
			get {
				return this._trust;
			}
		}
		
		/// <value>
		/// The creation date of the ID (seconds from Epoch)
		/// </value>
		public string CreationDate {
			get {
				return this._creationDate;
			}
		}
		
		/// <value>
		/// The expiration date of the ID (seconds from Epoch)
		/// </value>
		public string ExpirationDate {
			get {
				return this._expirationDate;
			}
		}
		
		/// <value>
		/// The unique hash of the ID.
		/// </value>
		public string Hash {
			get {
				return this._hash;
			}
		}
		
		/// <value>
		/// The name.
		/// </value>
		public string Name {
			get {
				return this._name;
			}
		}
		
		/// <value>
		/// The comment, if present.
		/// </value>
		public string Comment {
			get {
				return this._comment;
			}
		}
		
		/// <value>
		/// The e-mail address.
		/// </value>
		public string Email {
			get {
				return this._email;
			}
		}
		
		/// <value>
		/// Signatures on this UID/UAT.
		/// </value>
		public ArrayList Signatures {
			get {
				return this.GetSignatures(this._keyid, this.Hash);
			}
		}
	}
}
