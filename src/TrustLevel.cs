// TrustLevels.cs
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
	/// Trust levels
	/// </summary>
	public enum TrustLevel {
		/// <summary>
		/// Unknown trust (new to the system)
		/// </summary>
		UnknownNew,
		/// <summary>
		/// Invalid key (e.g. due to missing self-signature)
		/// </summary>
		Invalid,
		/// <summary>
		/// The key has been disabled (deprecated - use the 'D' in field 12
		/// instead)
		/// </summary>
		Disabled,
		/// <summary>
		/// The key has been revoked
		/// </summary>
		Revoked,
		/// <summary>
		/// The key has expired
		/// </summary>
		Expired,
		/// <summary>
		/// Unknown trust (i.e. no value assigned)
		/// </summary>
		Unknown,
		/// <summary>
		/// Undefined trust
		/// </summary>
		Undefined,
		/// <summary>
		/// Don't trust this key at all
		/// </summary>
		Never,
		/// <summary>
		/// There is marginal trust in this key
		/// </summary>
		Marginal,
		/// <summary>
		/// The key is fully truted
		/// </summary>
		Full,
		/// <summary>
		/// The key is ultimately trusted
		/// </summary>
		/// <para>This often means that the secret key is available, but any key
		/// may be marked as ultimately trusted.</para>
		Ultimate,
	}
}
