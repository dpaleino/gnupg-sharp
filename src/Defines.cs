// Defines.cs
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
using System.Text.RegularExpressions;

namespace GnuPG
{
	/// <summary>
	/// General usage definitions
	/// </summary>
	public static class Defines
	{
		/// <summary>
		/// Defines a regular expression to match e-mail addresses (case insensitive).
		/// </summary>
		/// <remarks>
		/// This is (quasi-)per-RFC2822 §3.4.1:
		/// http://tools.ietf.org/html/rfc2822#section-3.4.1
		/// We dropped the ""@[] syntax.
		/// </remarks>
		public static string EmailRegex = @"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?";
		
		/// <summary>
		/// Defines a regular expression to match "canonical" GPG UID fields:
		///    Joe User (Comment) &lt;joe@user.com&gt;
		/// </summary>
		public static string UIDRegex = @"([._+\w\s]+)( \(([^\)]*)\))? <("+EmailRegex+")>";
	}
}
