// GPG.cs
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
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace GnuPG {
	/// <summary>
	/// Main class
	/// </summary>
	public class GPG {
		private string _homedir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal), ".gnupg");
		private string _secretKeyring;
		private string _publicKeyring;
		private Commands _command = Commands.List;
		private bool _armor = true;
//		private string _passphrase = "";
		private int _timeoutms = 10000;
		private string _key;
		private int _exitcode;
		private VerbosityLevel _verbosity = VerbosityLevel.None;
	
		private Process _processObject;
		
		/// <summary>
		/// Main constructor.
		/// </summary>
		public GPG () {
			Initialize();
		}
		
		/// <summary>
		/// Main constructor.
		/// </summary>
		/// <param name="homedir">
		/// A <see cref="System.String"/> representing the directory where gnupg
		/// stores its data. If not specified, the default is ~/.gnupg/.
		/// </param>
		public GPG (string homedir) {
			this._homedir = homedir;
			Initialize();
		}

		/// <summary>
		/// Main constructor.
		/// </summary>
		/// <param name="KeyID">
		/// A <see cref="System.String"/>, the Key ID to work on.
		/// </param>
		/// <param name="Command">
		/// A <see cref="Commands"/>, the Command to execute.
		/// </param>
		public GPG (string KeyID, Commands Command) {
			this._key = KeyID;
			this._command = Command;
			Initialize();
		}
		
		private void Initialize() {
			this.PublicKeyring = Path.Combine(this.HomeDirectory, "pubring.gpg");
			this.SecretKeyring = Path.Combine(this.HomeDirectory, "secring.gpg");
		}
		
		/// <value>
		/// The command to execute. The default is Commands.List.
		/// </value>
		public Commands Command {
			set {
				this._command = value;
			}
			get {
				return this._command;
			}
		}
		
		/// <value>
		/// Should the output be armored? Default is true.
		/// </value>
		public bool Armor {
			set {
				this._armor = value;
			}
			get {
				return this._armor;
			}
		}

		/// <value>
		/// The timeout for the GPG process. Default is 10 seconds.
		/// </value>
		public int TimeoutMs {
			set {
				this._timeoutms = value;
			}
			get {
				return this._timeoutms;
			}
		}
		
		/// <value>
		/// The raw output from the process.
		/// </value>
		public string Output {
			get {
				return this._outputString;
			}
		}
		
		/// <value>
		/// Error messages from the process.
		/// </value>
		public string Error {
			get {
				return this._errorString;
			}
		}
		
		/// <value>
		/// The arguments string passed to the gpg process.
		/// </value>
		public string Arguments {
			get {
				return OptionsString();
			}
		}
		
//		/// <summary>
//		/// Passphrase for using your private key - mandatory when
//		/// <see cref="Command">Command</see> is Sign or SignAndEncrypt.
//		/// </summary>
//		public string Passphrase
//		{
//			set
//			{
//				_passphrase = value;
//				if (_passphrase != "")
//					_passphrasefd = "0";
//				else
//					_passphrasefd = "";
//			}
//		}

		/// <value>
		/// The directory where the keyrings are kept. Defaults to ~/.gnupg/.
		/// </value>
		public string HomeDirectory {
			set {
				this._homedir = Path.GetFullPath(value);
			}
			get {
				return this._homedir;
			}
		}

		/// <value>
		/// The Key ID to work on.
		/// </value>
		public string KeyID {
			set {
				this._key = value;
			}
			get {
				return this._key;
			}
		}
		
//		/// <value>
//		/// The file descriptor to read the passphrase from.
//		/// </value>
//		public string PassphraseFD
//		{
//			set
//			{
//				_passphrasefd = value;
//			}
//		}
		
		/// <value>
		/// gpg's exit code.
		/// </value>
		public int ExitCode {
			get {
				return this._exitcode;
			}
		}
		
		/// <value>
		/// The verbosity gpg should be set to. Defaults to VerbosityLevel.None.
		/// </value>
		public VerbosityLevel Verbosity {
			set {
				this._verbosity = value;
			}
			get {
				return this._verbosity;
			}
		}
		
		/// <value>
		/// The secret keys keyring. Defaults to HomeDirectory/secring.gpg
		/// </value>
		public string SecretKeyring {
			set {
				this._secretKeyring = value;
			}
			get {
				return this._secretKeyring;
			}
		}
		
		/// <value>
		/// The public keys keyring. Defaults to HomeDirectory/pubring.gpg
		/// </value>
		public string PublicKeyring {
			set {
				this._publicKeyring = value;
			}
			get {
				return this._publicKeyring;
			}
		}
		
//		/// <summary>
//		/// The number of bits of the primary key.
//		/// </summary>
//		/// <param name="KeyID">
//		/// A <see cref="System.String"/>
//		/// </param>
//		/// <returns>
//		/// A <see cref="System.Int32"/>, the number of bits.
//		/// </returns>
//		public static int GetPrimaryKeyBits (string KeyID) {
//			// The number of bits is retrieved from the line:
//			//   pub:u:1024:17:E6AA90171392B174:2006-02-01:::u:David Paleino <d.paleino@gmail.com>::scaESCA:
//			GPG me = new GPG(KeyID, Commands.List);
//			me.Exec();
//			string[] output = me.Output.Split('\n');
//			foreach (string line in output) {
//				if ((line != "") && (line.Substring(0, 3) == "pub")) {
//					string[] fields = line.Split(':');
//					// The number of bits is the third field
//					return Convert.ToInt32(fields[2]);
//				} else {
//					continue;
//				}
//			}
//			throw new GPGException(me.Error);
//		}
//		
//		/// <summary>
//		/// The ID creation date.
//		/// </summary>
//		/// <param name="Email">
//		/// A <see cref="System.String"/>
//		/// </param>
//		/// <returns>
//		/// A <see cref="DateTime"/>
//		/// </returns>
//		public static DateTime GetCreationDate (string Email) {
//			UID_old id = new UID_old(Email);
//			return id.CreationDate;
//		}
		
		/// <summary>
		/// Returns an armored version of the public part of KeyID.
		/// </summary>
		/// <param name="KeyID">
		/// A <see cref="System.String"/>
		/// </param>
		/// <returns>
		/// A <see cref="System.String"/>, the armored version of the public key.
		/// </returns>
		public static string GetPublicKey (string KeyID) {
			GPG me = new GPG(KeyID, Commands.Export);
			me.Armor = true;
			me.Exec();
			return me.Output;
		}
		
		/// <summary>
		/// Returns an armored version of the secret part of KeyID.
		/// </summary>
		/// <param name="KeyID">
		/// A <see cref="System.String"/>
		/// </param>
		/// <returns>
		/// A <see cref="System.String"/>, the armored version of the secret key.
		/// </returns>
		public static string GetSecretKey (string KeyID) {
			GPG me = new GPG(KeyID, Commands.ExportSecretKey);
			me.Armor = true;
			me.Exec();
			return me.Output;
		}
		
		/// <summary>
		/// Returns a list of available secret keys.
		/// </summary>
		/// <returns>
		/// A <see cref="ArrayList"/>
		/// </returns>
		public static ArrayList GetAvailableSecretKeys () {
			GPG me = new GPG();
			me.Initialize();
			return GetAvailableSecretKeys(me.SecretKeyring);
		}
		
		/// <summary>
		/// Returns a list of available secret keys from <paramref name="SecretKeyring"/>.
		/// </summary>
		/// <param name="SecretKeyring">
		/// A <see cref="System.String"/>
		/// </param>
		/// <returns>
		/// A <see cref="ArrayList"/>
		/// </returns>
		public static ArrayList GetAvailableSecretKeys (string SecretKeyring) {
			ArrayList mySecretKeys = new ArrayList();
			GPG me = new GPG();
			me.Command = Commands.ListSecretKeys;
			me.SecretKeyring = SecretKeyring;
			me.Exec();
			string[] output = me.Output.Split('\n');
			foreach (string line in output) {
				if (Utils.GetRecordType(Utils.GetField(line, 0)) == RecordType.SecretKey) {
					mySecretKeys.Add(Utils.GetField(line, 4));
				} else {
					continue;
				}
			}
			return mySecretKeys;
		}
		
		// TODO: provide a method to directly save to file.
//		public static FileStream ExportPublicKey (string KeyID, string Filename) {
//			FileStream f = new System.IO.FileStream();
//		}
		
		/// <summary>
		/// Options string builder.
		/// </summary>
		/// <returns>
		/// A <see cref="System.String"/>, representing the arguments passed to
		/// gpg.
		/// </returns>
		protected string OptionsString ()
		{
			// we want to be sure that our *Keyring options get updated.
			Initialize();
			
			StringBuilder options = new StringBuilder("", 255);
//			bool needRecipient = false;
//			bool needPassphrase = false;
			
			// The --homedir argument should be the first one.
			options.AppendFormat("--homedir {0} ", HomeDirectory);

			options.Append("--fixed-list-mode ");
			
			// We manually specify the keyrings, so that we are *sure* that
			// we use what the user wants.
			options.AppendFormat("--no-default-keyring --keyring {0} ", PublicKeyring);
			options.AppendFormat("--secret-keyring {0} ", SecretKeyring);
			
			// The --armor option must come before the options needing it.
			if (_armor) {
				options.Append("--armor ");
			}
			
			switch (_command)
			{
//				case Commands.Sign:
//					options.Append("--clear ");
//					needPassphrase = true;
//					break;
//				case Commands.Decrypt:
//					options.Append("--decrypt ");
//					break;
//				case Commands.Import:
//					options.Append("--import ");
//					break;
				case Commands.List:
					options.AppendFormat("--list-sigs --fingerprint --fingerprint --with-colons {0} ", KeyID);
					break;
				case Commands.ListSecretKeys:
					options.Append("--list-secret-keys --with-colons ");
					break;
				case Commands.Export:
					options.AppendFormat("--export {0} ", KeyID);
					break;
				case Commands.ExportSecretKey:
					options.AppendFormat("--export-secret-keys {0} ", KeyID);
					break;
//				case Commands.SignKey:
//					options.Append("--sign-key ");
//					needPassphrase = true;
//					break;
//				case Commands.AddKey:
//					options.Append("--import ");
//					break;
//				case Commands.DelKey:
//					options.Append("--delete-key ");
//					break;
				default:
					throw new GPGException("command not yet implemented, or non existant!");
			}
//			if (_recipient != null && _recipient != "")
//				options.Append(String.Format("--recipient {0} ", _recipient));
//			else
//				if (needRecipient)
//					throw new GPGException("GPG: Missing recipient, cannot continue.");
//			
//			if (_originator != null && _originator != "")
//				options.Append(String.Format("--default-key {0} ", _originator));
			
//			if (_passphrase == null || _passphrase == "")
//				if (needPassphrase)
//					throw new GPGException("GPG: Passphrase not provided, cannot continue.");
//			
//			if (_passphrasefd != null && _passphrasefd != "")
//				options.Append(String.Format("--passphrase-fd {0} ", _passphrasefd));
//			else
//				if (needPassphrase && (_passphrase == null || _passphrase == ""))
//					throw new GPGException("Passphrase not provided, cannot continue.");
			
			switch (_verbosity)
			{
				case VerbosityLevel.None:
					options.Append("--no-verbose ");
					break;
				case VerbosityLevel.Verbose:
					options.Append("--verbose ");
					break;
				case VerbosityLevel.VeryVerbose:
					options.Append("--verbose --verbose ");
					break;
			}
			
			
			return options.ToString();
		}
		
		/// <summary>
		/// Start the gpg process.
		/// </summary>
		public void Exec () {
			ProcessStartInfo pInfo = new ProcessStartInfo("/usr/bin/gpg", OptionsString());
			pInfo.WorkingDirectory = "/usr/bin";
			pInfo.CreateNoWindow = true;
			pInfo.UseShellExecute = false;
			pInfo.RedirectStandardInput = true;
			pInfo.RedirectStandardOutput = true;
			pInfo.RedirectStandardError = true;
			pInfo.StandardErrorEncoding = Encoding.UTF8;
			pInfo.StandardOutputEncoding = Encoding.UTF8;
			
			try {
				_processObject = Process.Start(pInfo);
			} catch {}
			
			ThreadStart outputEntry = new ThreadStart(StandardOutputReader);
			Thread outputThread = new Thread(outputEntry);
			outputThread.Start();
			ThreadStart errorEntry = new ThreadStart(StandardErrorReader);
			Thread errorThread = new Thread(errorEntry);
			errorThread.Start();
			
			_processObject.StandardInput.Close();
			
			if (_processObject.WaitForExit(TimeoutMs)) {
				// The process ended before the Timeout
				if (!outputThread.Join(TimeoutMs)) {
					outputThread.Abort();
				}
				if (!errorThread.Join(TimeoutMs)) {
					errorThread.Abort();
				}
			}
			else {
				_outputString = "";
				_errorString = String.Format("Timed out after {0} milliseconds.", TimeoutMs.ToString());
				_processObject.Kill();
				
				// Process timed out.. kill it.
				if (outputThread.IsAlive) {
					outputThread.Abort();
				}
				if (errorThread.IsAlive) {
					errorThread.Abort();
				}
			}
			
			// Check the results
			_exitcode = _processObject.ExitCode;
			if (_exitcode != 0) {
				if (_errorString == "") {
					throw new GPGException(String.Format("[{0}]: Unknown error.", _processObject.ExitCode.ToString())); 
				}
			}
		}
		
		/// <summary>
		/// Reader thread for standard output.
		/// <para>Updates the private variable _outputString (locks it first)</para>
		/// </summary>
		public void StandardOutputReader() {
			string output = _processObject.StandardOutput.ReadToEnd();
			lock (this) {
				_outputString = output;
			}
		}
		
		/// <summary>
		/// Reader thread for standard error.
		/// <para>Updates the private variable _errorString (locks it first)</para>
		/// </summary>
		public void StandardErrorReader() {
			string error = _processObject.StandardError.ReadToEnd();
			lock (this) {
				_errorString = error;
			}
		}
		
		// Helper variables
		private string _outputString;
		private string _errorString;
		
#region Helper utilities
//		private object<T> 
#endregion
    }
}