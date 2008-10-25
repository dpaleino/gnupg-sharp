// Algorithm.cs
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
	/// Key algorithms.
	/// </summary>
	// TODO: list *ALL* Algorithms here, see include/cipher.h in gnupg's source.
	public enum Algorithm {
		/// <summary>
		/// 1 - RSA
		/// </summary>
		RSA,
		/// <summary>
		/// 2 - RSA (encrypt only)
		/// </summary>
		RSAEncryptOnly,
		/// <summary>
		/// 3 - RSA (sign only)
		/// </summary>
		RSASignOnly,
		/// <summary>
		/// 16 - Elgamal (encrypt only)
		/// </summary>
		ElgamalEncryptOnly,
		/// <summary>
		/// 17 - DSA (sometimes called DH, sign only)
		/// </summary>
		DSA,
		/// <summary>
		/// 20 - Elgamal (sign and encrypt - don't use them!)
		/// </summary>
		ElgamalSignAndEncrypt,
		
		/// <summary>
		/// Unknown
		/// </summary>
		Unknown,
	}
}
