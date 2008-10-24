// Keyset.cs
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
	/// Represents a Keyset: Primary Key + Secondary Key(s).
	/// </summary>
	public class Keyset {
		private Key _primaryKey;
		private ArrayList _subkeys;
		
		/// <summary>
		/// Main constructor.
		/// </summary>
		/// <param name="KeyID">
		/// A <see cref="System.String"/>, the exact key ID (8 or 16 chars,
		/// with or without preceding 0x / 0X).
		/// </param>
		public Keyset(string KeyID) {
			// Remove the 0{x,X} from the KeyID.
			KeyID = KeyID.Replace("0x", "").Replace("0X", "");
			if ((KeyID.Length != 8) && (KeyID.Length != 16)) {
				throw new GPGException(String.Format("invalid KeyID ({0}) to build Keyset object.", KeyID));
			}
			
			KeyID = "0x"+KeyID;
			GPG gpg = new GPG(KeyID, Commands.List);
			gpg.Exec();
			
			string[] output = gpg.Output.Split('\n');
			this._subkeys = new ArrayList();
			
			DateTime start = DateTime.Now;
			foreach (string line in output) {
				string tag = Utils.GetField(line, 0);
				
				// TODO: what else a keyset can contain?
				
				// Store the public primary key.
				if (Utils.GetRecordType(tag) == RecordType.PublicKey) {
					// The line is in the form:
					//   pub:u:1024:17:E6AA90171392B174:1138786427:::u:::scaESCA:
					DateTime kstart = DateTime.Now;
					this._primaryKey = new Key(Utils.GetField(line, 4));
					Console.WriteLine("PrimaryKey: "+DateTime.Now.Subtract(kstart).ToString());
				}
				// Store the subkey.
				else if (Utils.GetRecordType(tag) == RecordType.Subkey) {
					// The line is in the form:
					//   sub:u:4096:1:BB45ABF7A71D5481:1203325654::::::e:
					DateTime kstart = DateTime.Now;
					this._subkeys.Add(new Key(Utils.GetField(line, 4)));
					Console.WriteLine("SubKey: "+DateTime.Now.Subtract(kstart).ToString());
				}
			}
			Console.WriteLine("Keyset foreach: "+DateTime.Now.Subtract(start).ToString());
		}
		
		/// <value>
		/// The primary key of the keyset (/^pub/)
		/// </value>
		public Key PrimaryKey {
			get {
				return this._primaryKey;
			}
		}
		
		/// <value>
		/// An array of subkeys of the keyset (/^sub/)
		/// </value>
		public ArrayList Subkeys {
			get {
				return this._subkeys;
			}
		}
	}
}
