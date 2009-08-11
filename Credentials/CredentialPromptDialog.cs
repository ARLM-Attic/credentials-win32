using System;
using System.Collections.Generic;
using System.Text;
using System.Drawing;
using System.Security;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.ComponentModel;
using System.Windows.Forms;
using System.Runtime.ConstrainedExecution;
using Evb.Runtime.InteropServices;

namespace Evb.Security.Credentials
{
    [DesignerCategory("Dialogs"), Designer("System.ComponentModel.Design.ComponentDesigner, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")]
    [ToolboxBitmap(typeof(Resources.Resources), "CredentialPromptDialog.bmp")]
    [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
    public sealed class CredentialPromptDialog : Component
    {
        #region Constants

        /// <summary>
        /// Maximum length of the various credential string fields (in characters).
        /// </summary>
        private const int CRED_MAX_STRING_LENGTH = 256;

        /// <summary>
        /// Maximum length of the UserName field. The worst case is &lt;User&gt;@&lt;DnsDomain&gt;.
        /// </summary>
        private const int CRED_MAX_USERNAME_LENGTH = 256 + 1 + 256;

        /// <summary>
        /// Maximum length of the TargetName field for CRED_TYPE_GENERIC (in characters).
        /// </summary>
        private const int CRED_MAX_GENERIC_TARGET_NAME_LENGTH = 32767;

        /// <summary>
        /// Maximum length of the TargetName field for CRED_TYPE_DOMAIN_* (in characters)
        ///     Largest one is &lt;DfsRoot&gt;\&lt;DfsShare&gt;.
        /// </summary>
        private const int CRED_MAX_DOMAIN_TARGET_NAME_LENGTH = 256 + 1 + 80;

        /// <summary>
        /// Maximum length of a target namespace.
        /// </summary>
        private const int CRED_MAX_TARGETNAME_NAMESPACE_LENGTH = 256;

        /// <summary>
        /// Maximum length of a target attribute.
        /// </summary>
         private const int CRED_MAX_TARGETNAME_ATTRIBUTE_LENGTH = 256;

        /// <summary>
        /// Maximum size of the Credential Attribute Value field (in bytes).
        /// </summary>
        private const int CRED_MAX_VALUE_SIZE = 256;

        /// <summary>
        /// Maximum number of attributes per credential.
        /// </summary>
        private const int CRED_MAX_ATTRIBUTES = 64;

        private const int CRED_MAX_CREDENTIAL_BLOB_SIZE = 512;

        // String length limits:
        private const int CREDUI_MAX_MESSAGE_LENGTH = 32767;
        private const int CREDUI_MAX_CAPTION_LENGTH = 128;
        private const int CREDUI_MAX_GENERIC_TARGET_LENGTH = CRED_MAX_GENERIC_TARGET_NAME_LENGTH;
        private const int CREDUI_MAX_DOMAIN_TARGET_LENGTH = CRED_MAX_DOMAIN_TARGET_NAME_LENGTH;
        private const int CREDUI_MAX_USERNAME_LENGTH = CRED_MAX_USERNAME_LENGTH;
        private const int CREDUI_MAX_PASSWORD_LENGTH = CRED_MAX_CREDENTIAL_BLOB_SIZE / 2;
        
        #endregion

        #region Fields

        private Bitmap _banner;
        private bool _confirmed;
        private CredUIFlags _options = CredUIFlags.ExpectConfirmation;
        private string _message = String.Empty;
        private string _caption;
        private SecureString _password;
        private bool _saveChecked;
        private string _targetName = String.Empty;
        private string _userName = String.Empty;

        #endregion

        #region Methods

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public void ConfirmCredentials()
        {
            this.CheckNotDisposed();
            var result = NativeMethods.CredUIConfirmCredentials(_targetName, true);
            this._confirmed = true;

            // TODO: clarify why sometimes it returns error even when called in the right time
            /*if (result != CredUIReturnCodes.NO_ERROR)
            {
                throw new Win32Exception((int)result);
            }*/
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public DialogResult ShowDialog()
        {
            this.CheckNotDisposed();
            return this.ShowDialog(null);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public DialogResult ShowDialog(IWin32Window owner)
        {
            if (String.IsNullOrEmpty(_targetName)) throw new ArgumentNullException("TargetName");

            DialogResult result;
            int passwordMaxLength = CREDUI_MAX_PASSWORD_LENGTH + 1;
            StringBuilder username = new StringBuilder(_userName, CREDUI_MAX_USERNAME_LENGTH);
            SafeBitmapHandle banner = _banner != null ? new SafeBitmapHandle(_banner.GetHbitmap(), true) : new SafeBitmapHandle(IntPtr.Zero, false);
            SafeUnmanagedBuffer password = new SafeUnmanagedBuffer(passwordMaxLength * sizeof(char));
            for (int i = 0; i < sizeof(char); i++) password[i] = 0;

            CheckNotDisposed();

            var info = new NativeMethods.CREDUI_INFO()
            {
                hwndParent = owner != null ? owner.Handle : IntPtr.Zero,
                hbmBanner = banner.DangerousGetHandle(),
                pszCaptionText = _caption,
                pszMessageText = _message

            };
            info.cbSize = Marshal.SizeOf(info);

            try
            {
                var nativeResult = NativeMethods.CredUIPromptForCredentials(ref info, _targetName, IntPtr.Zero, 0,
                    username, CRED_MAX_USERNAME_LENGTH,
                    new HandleRef(password, password.DangerousGetHandle()), passwordMaxLength,
                    ref _saveChecked, _options);

                /*IntPtr outBuffer;
                uint authPackage = 0;
                uint outBufferSize;
                info.hbmBanner = IntPtr.Zero;
                nativeResult = NativeMethods.CredUIPromptForWindowsCredentials(ref info, 0, ref authPackage, new HandleRef(null, IntPtr.Zero), 0, out outBuffer, out outBufferSize, ref _saveChecked,
                    0x1 | 0x200);
                
                int nameLen = 0, passLen = 0, dNameLength = 0;
                NativeMethods.CredUnPackAuthenticationBuffer(0, outBuffer, (int)outBufferSize, null, ref nameLen, null, ref dNameLength, null, ref passLen);
                StringBuilder sName = new StringBuilder(nameLen), sPass = new StringBuilder(passLen), dName = new StringBuilder(dNameLength);
                bool pos = NativeMethods.CredUnPackAuthenticationBuffer(0, outBuffer, (int)outBufferSize, sName, ref nameLen,
                    dName, ref dNameLength, sPass, ref passLen);


                var b = new SafeCoUnmanagedBuffer(outBuffer, checked((int)outBufferSize), true);

                string s = Marshal.PtrToStringUni(outBuffer);*/
                
                switch (nativeResult)
                {
                    case NativeMethods.CredUIReturnCodes.NO_ERROR:
                        _userName = username.ToString();

                        Password.Clear();
                        byte[] unicodeBytes = new byte[sizeof(char)];
                        char currentChar = Char.MaxValue;
                        for (int i = 0; ;)
                        {
                            for (int j = 0; j < sizeof(char); j++)
                            {
                                unicodeBytes[j] = password[i];
                                password[i++] = 0;
                            }

                            if ((currentChar = Encoding.Unicode.GetChars(unicodeBytes)[0]) != '\0')
                                Password.AppendChar(currentChar);
                            else break;
                        }

                        result = DialogResult.OK;
                        break;

                    case NativeMethods.CredUIReturnCodes.ERROR_CANCELLED:
                        result = DialogResult.Cancel;
                        break;

                    default:
                        throw new Win32Exception((int)nativeResult);
                }
            }
            finally
            {
                banner.Dispose();
                password.Dispose();
            }

            return result;
        }

        #endregion

        #region Properties

        #region Behavior category

        /// <summary>
        /// Specifies whether a user interface will be shown even if the credentials can be returned from an existing credential in credential manager.
        /// This flag is permitted only if <see cref="GenericCredentials"/> is also true.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("Specifies whether a user interface will be shown even if the credentials can be returned from an existing credential in credential manager. This flag is permitted only if GenericCredentials is also true.")]
        public bool AlwaysShowUI
        {
            get { return GetOption(CredUIFlags.AlwaysShowUI); }
            set { SetOption(CredUIFlags.AlwaysShowUI, value); }
        }

        [Category("Behavior")]
        [DefaultValue(false)]
        public bool CompleteUserName
        {
            get { return GetOption(CredUIFlags.CompleteUserName); }
            set { SetOption(CredUIFlags.CompleteUserName, value); }
        }

        /// <summary>
        /// Do not store credentials or display check boxes. You can set <see cref="ShowSaveCheckBox"/> with this flag to display the Save check box only, and the result is returned in the <see cref="Save"/> property.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("Do not store credentials or display check boxes. You can set ShowSaveCheckBox with this flag to display the Save check box only, and the result is returned in the Save property.")]
        public bool DoNotPersist
        {
            get { return GetOption(CredUIFlags.DoNotPersist); }
            set { SetOption(CredUIFlags.DoNotPersist, value); }
        }

        /// <summary>
        /// Populate the combo box with user name/password only. Do not display certificates or smart cards in the combo box.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("Populate the combo box with user name/password only. Do not display certificates or smart cards in the combo box.")]
        public bool ExcludeCertificate
        {
            get { return GetOption(CredUIFlags.ExcludeCertificate); }
            set { SetOption(CredUIFlags.ExcludeCertificate, value); }
        }

        /// <summary>
        /// Specifies that the caller will call <see cref="ConfirmCredentials"/> after checking to determine whether the returned credentials are actually valid. This mechanism ensures that credentials that are not valid are not saved to the credential manager. Specify this flag in all cases unless <see cref="DoNotPersist"/> is specified.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(true)]
        [Description("Specifies that the caller will call ConfirmCredentials after checking to determine whether the returned credentials are actually valid. This mechanism ensures that credentials that are not valid are not saved to the credential manager. Specify this flag in all cases unless DoNotPersist is specified.")]
        public bool ExpectConfirmation
        {
            get { return GetOption(CredUIFlags.ExpectConfirmation); }
            set { SetOption(CredUIFlags.ExpectConfirmation, value); }
        }

        /// <summary>
        /// Consider the credentials entered by the user to be generic credentials.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("Consider the credentials entered by the user to be generic credentials.")]
        public bool GenericCredentials
        {
            get { return GetOption(CredUIFlags.GenericCredentials); }
            set { SetOption(CredUIFlags.GenericCredentials, value); }
        }

        /// <summary>
        /// Notify the user of insufficient credentials by displaying the "Logon unsuccessful" balloon tip.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("Notify the user of insufficient credentials by displaying the \"Logon unsuccessful\" balloon tip.")]
        public bool IncorrectPassword
        {
            get { return GetOption(CredUIFlags.IncorrectPassword); }
            set { SetOption(CredUIFlags.IncorrectPassword, value); }
        }

        /// <summary>
        /// Don't allow the user to change the supplied username.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("Don't allow the user to change the supplied username.")]
        public bool KeepUserName
        {
            get { return GetOption(CredUIFlags.KeepUserName); }
            set { SetOption(CredUIFlags.KeepUserName, value); }
        }

        [Category("Behavior")]
        [DefaultValue(false)]
        public bool PasswordOnlyOk
        {
            get { return GetOption(CredUIFlags.PasswordOnlyOk); }
            set { SetOption(CredUIFlags.PasswordOnlyOk, value); }
        }

        /// <summary>
        /// Do not show the Save check box, but the credential is saved as though the box were shown and selected.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("Do not show the Save check box, but the credential is saved as though the box were shown and selected.")]
        public bool Persist
        {
            get { return GetOption(CredUIFlags.Persist); }
            set { SetOption(CredUIFlags.Persist, value); }
        }

        /// <summary>
        /// Populate the combo box with local administrators only.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("Populate the combo box with local administrators only.")]
        public bool RequestAdministrator
        {
            get { return GetOption(CredUIFlags.RequestAdministrator); }
            set { SetOption(CredUIFlags.RequestAdministrator, value); }
        }

        /// <summary>
        /// Populate the combo box with certificates and smart cards only. Do not allow a user name to be entered.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("Populate the combo box with certificates and smart cards only. Do not allow a user name to be entered.")]
        public bool RequireCertificate
        {
            get { return GetOption(CredUIFlags.RequireCertificate); }
            set { SetOption(CredUIFlags.RequireCertificate, value); }
        }

        /// <summary>
        /// Populate the combo box with certificates or smart cards only. Do not allow a user name to be entered.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("Populate the combo box with certificates or smart cards only. Do not allow a user name to be entered.")]
        public bool RequireSmartcard
        {
            get { return GetOption(CredUIFlags.RequireSmartcard); }
            set { SetOption(CredUIFlags.RequireSmartcard, value); }
        }

        /// <summary>
        /// 
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("")]
        public bool ServerCredential
        {
            get { return GetOption(CredUIFlags.ServerCredential); }
            set { SetOption(CredUIFlags.ServerCredential, value); }
        }

        /// <summary>
        /// If the check box is selected, show the Save check box and return <code>true</code> in the <see cref="Save"/> property, otherwise, return <code>false</code>. <see cref="DoNotPersist"/> must be enabled to use this flag. Check box uses the value in <see cref="Save"/> property by default.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("If the check box is selected, show the Save check box and return true in the Save property, otherwise, return false. DoNotPersist must be enabled to use this flag. Check box uses the value in Save property by default.")]
        public bool ShowSaveCheckBox
        {
            get { return GetOption(CredUIFlags.ShowSaveCheckBox); }
            set { SetOption(CredUIFlags.ShowSaveCheckBox, value); }
        }

        /// <summary>
        /// Credential has a username as the target.
        /// </summary>
        [Category("Behavior")]
        [DefaultValue(false)]
        [Description("Credential has a username as the target.")]
        public bool UserNameTargetCredentials
        {
            get { return GetOption(CredUIFlags.UserNameTargetCredentials); }
            set { SetOption(CredUIFlags.UserNameTargetCredentials, value); }
        }

        [Category("Behavior")]
        [DefaultValue(false)]
        public bool ValidateUserName
        {
            get { return GetOption(CredUIFlags.ValidateUserName); }
            set { SetOption(CredUIFlags.ValidateUserName, value); }
        }

        private bool GetOption(CredUIFlags option)
        {
            return (_options & option) != 0;
        }

        private void SetOption(CredUIFlags option, bool value)
        {
            if (value)
            {
                switch (option)
                {
                    // The flags CREDUI_FLAGS_REQUIRE_SMARTCARD, CREDUI_FLAGS_REQUIRE_CERTIFICATE,
                    // and CREDUI_FLAGS_EXCLUDE_CERTIFICATE are mutually exclusive.
                    case CredUIFlags.ExcludeCertificate:
                    case CredUIFlags.RequireCertificate:
                    case CredUIFlags.RequireSmartcard:
                        SetOption(CredUIFlags.ExcludeCertificate, false);
                        SetOption(CredUIFlags.RequireCertificate, false);
                        SetOption(CredUIFlags.RequireSmartcard, false);
                        break;

                    // CREDUI_FLAGS_DO_NOT_PERSIST must be specified to use this flag. Check box uses the value in pfSave by default.
                    case CredUIFlags.ShowSaveCheckBox:
                        SetOption(CredUIFlags.DoNotPersist, true);
                        break;

                    // This flag is permitted only if CREDUI_FLAGS_GENERIC_CREDENTIALS is also specified.
                    case CredUIFlags.AlwaysShowUI:
                        SetOption(CredUIFlags.GenericCredentials, true);
                        break;

                    // The flags CREDUI_FLAG_USERNAME_TARGET_CREDENTIALS and CREDUI_FLAGS_GENERIC_CREDENTIALS are mutually exclusive.
                    case CredUIFlags.GenericCredentials:
                    case CredUIFlags.UserNameTargetCredentials:
                        SetOption(CredUIFlags.GenericCredentials, false);
                        SetOption(CredUIFlags.GenericCredentials, false);
                        break;
                }
                _options |= option;
            }
            else
            {
                // DoNotPersist must be specified to use ShowSaveCheckBox flag.
                if (option == CredUIFlags.DoNotPersist) SetOption(CredUIFlags.ShowSaveCheckBox, false);

                _options &= ~option;
            }
        }

        #endregion

        #region Appearance category

        [Category("Appearance")]
        public bool SaveChecked
        {
            [return: MarshalAs(UnmanagedType.U1)]
            get
            {
                this.CheckNotDisposed();
                return this._saveChecked;
            }
            [param: MarshalAs(UnmanagedType.U1)]
            set
            {
                this.CheckNotDisposed();
                this._saveChecked = value;
            }
        }

        /// <summary>
        /// Bitmap to display in the dialog box. If this member is <code>null</code>, a default bitmap is used. The bitmap size is limited to 320x60 pixels.
        /// </summary>
        [Category("Appearance")]
        [Description("Bitmap to display in the dialog box. If this member is null, a default bitmap is used. The bitmap size is limited to 320x60 pixels.")]
        public Bitmap Banner
        {
            get
            {
                this.CheckNotDisposed();
                return this._banner;
            }
            set
            {
                this.CheckNotDisposed();
                if (value != this._banner)
                {
                    IDisposable banner = this._banner;
                    if (banner != null)
                    {
                        banner.Dispose();
                    }
                    this._banner = value;
                }
            }
        }

        /// <summary>
        /// A brief message to display in the dialog box.
        /// </summary>
        [Category("Appearance")]
        [DefaultValue("")]
        [Description("A brief message to display in the dialog box.")]
        public string Message
        {
            get
            {
                CheckNotDisposed();
                return _message;
            }
            set
            {
                CheckNotDisposed();
                if (null == value) throw new ArgumentNullException("value");
                if (CREDUI_MAX_MESSAGE_LENGTH < value.Length) throw new ArgumentOutOfRangeException("value");

                _message = value;
            }
        }

        /// <summary>
        /// The title for the dialog box.
        /// </summary>
        [Category("Appearance")]
        [Description("The title for the dialog box.")]
        public string Caption
        {
            get { return _caption; }
            set
            {
                if (_caption != value)
                {
                    if (CREDUI_MAX_CAPTION_LENGTH < value.Length) throw new ArgumentOutOfRangeException("value");

                    _caption = value;
                }
            }
        }

        #endregion

        /*[EditorBrowsable(EditorBrowsableState.Advanced)]
        [Browsable(false)]
        public int ErrorCode
        {
            get
            {
                this.CheckNotDisposed();
                return this._errorCode;
            }
            set
            {
                this.CheckNotDisposed();
                this._errorCode = value;
            }
        }*/

        [Browsable(false)]
        public SecureString Password
        {
            get
            {
                this.CheckNotDisposed();
                if (null == this._password)
                {
                    this._password = new SecureString();
                }
                return this._password;
            }
            set
            {
                this.CheckNotDisposed();
                if (null == value)
                {
                    throw new ArgumentNullException("value");
                }
                if (this._password != value)
                {
                    IDisposable password = this._password;
                    if (password != null)
                    {
                        password.Dispose();
                    }
                    this._password = value;
                }
            }
        }

        /// <summary>
        /// The name of the target for the credentials, typically a server name. For Distributed File System (DFS) connections, this string is of the form <example>ServerName\ShareName</example>. This parameter is used to identify target information when storing and retrieving credentials.
        /// </summary>
        [Description(@"The name of the target for the credentials, typically a server name. For Distributed File System (DFS) connections, this string is of the form ServerName\ShareName. This parameter is used to identify target information when storing and retrieving credentials.")]
        public string TargetName
        {
            get
            {
                this.CheckNotDisposed();
                return this._targetName;
            }
            set
            {
                this.CheckNotDisposed();
                if (null == value) throw new ArgumentNullException();
                if ((_options & CredUIFlags.GenericCredentials) == CredUIFlags.GenericCredentials)
                {
                    if (value.Length > CREDUI_MAX_GENERIC_TARGET_LENGTH) throw new ArgumentOutOfRangeException();
                }
                else if (value.Length > CREDUI_MAX_DOMAIN_TARGET_LENGTH) throw new ArgumentOutOfRangeException();

                this._targetName = value;
            }
        }

        /// <summary>
        /// User name for the credentials.
        /// </summary>
        [Description("User name for the credentials.")]
        public string UserName
        {
            get
            {
                this.CheckNotDisposed();
                return this._userName;
            }
            set
            {
                this.CheckNotDisposed();
                if (null == value)
                {
                    throw new ArgumentNullException("value");
                }
                if (0x201 < value.Length)
                {
                    throw new ArgumentOutOfRangeException("value");
                }
                this._userName = value;
            }
        }

        #endregion

        #region Dispose pattern

        // Track whether Dispose has been called.
        private bool _disposed;

        // Dispose(bool disposing) executes in two distinct scenarios.
        // If disposing equals true, the method has been called directly
        // or indirectly by a user's code. Managed and unmanaged resources
        // can be disposed.
        // If disposing equals false, the method has been called by the
        // runtime from inside the finalizer and you should not reference
        // other objects. Only unmanaged resources can be disposed.
        protected override void Dispose(bool disposing)
        {
            // Check to see if Dispose has already been called.
            if (!this._disposed)
            {
                // If disposing equals true, dispose all managed
                // and unmanaged resources.
                if (disposing)
                {
                    // Dispose managed resources.

                    IDisposable password = this._password;
                    if (password != null) password.Dispose();
                    this._password = null;

                    IDisposable banner = this._banner;
                    if (banner != null) banner.Dispose();
                    this._banner = null;

                    if (SaveChecked && ((_options & CredUIFlags.ExpectConfirmation) == CredUIFlags.ExpectConfirmation) && !_confirmed)
                        NativeMethods.CredUIConfirmCredentials(_targetName, false);
                }

                // Call the appropriate methods to clean up
                // unmanaged resources here.
                // If disposing is false,
                // only the following code is executed.

                // Note disposing has been done.
                _disposed = true;
            }

            base.Dispose(disposing);
        }

        private void CheckNotDisposed()
        {
            if (this._disposed)
            {
                //throw new ObjectDisposedException(string.Empty, Properties.Resources.ObjectDisposedExceptionMessage);
            }
        }

        #endregion

        #region Native methods

        [Flags]
        internal enum CredUIFlags
        {
            None = 0x00000,
            /// <summary>
            /// Notify the user of insufficient credentials by displaying the "Logon unsuccessful" balloon tip.
            /// </summary>
            IncorrectPassword = 0x00001,
            /// <summary>
            /// Do not store credentials or display check boxes. You can pass CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX with this flag to display the Save check box only, and the result is returned in the pfSave output parameter.
            /// </summary>
            DoNotPersist = 0x00002,
            /// <summary>
            /// Populate the combo box with local administrators only.
            /// </summary>
            /// <remarks><c></c>Windows XP Home Edition: This flag will filter out the well-known Administrator account.</remarks>
            RequestAdministrator = 0x00004,
            /// <summary>
            /// Populate the combo box with user name/password only. Do not display certificates or smart cards in the combo box.
            /// </summary>
            ExcludeCertificate = 0x00008,
            /// <summary>
            /// Populate the combo box with certificates and smart cards only. Do not allow a user name to be entered.
            /// </summary>
            RequireCertificate = 0x00010,
            /// <summary>
            /// If the check box is selected, show the Save check box and return TRUE in the pfSave output parameter, otherwise, return FALSE. CREDUI_FLAGS_DO_NOT_PERSIST must be specified to use this flag. Check box uses the value in pfSave by default.
            /// </summary>
            ShowSaveCheckBox = 0x00040,
            /// <summary>
            /// Specifies that a user interface will be shown even if the credentials can be returned from an existing credential in credential manager. This flag is permitted only if CREDUI_FLAGS_GENERIC_CREDENTIALS is also specified.
            /// </summary>
            AlwaysShowUI = 0x00080,
            /// <summary>
            /// Populate the combo box with certificates or smart cards only. Do not allow a user name to be entered.
            /// </summary>
            RequireSmartcard = 0x00100,
            PasswordOnlyOk = 0x00200,
            ValidateUserName = 0x00400,
            CompleteUserName = 0x00800,
            /// <summary>
            /// Do not show the Save check box, but the credential is saved as though the box were shown and selected.
            /// </summary>
            Persist = 0x01000,
            /// <summary>
            /// This flag is meaningful only in locating a matching credential to prefill the dialog box, should authentication fail. When this flag is specified, wildcard credentials will not be matched. It has no effect when writing a credential. CredUI does not create credentials that contain wildcard characters. Any found were either created explicitly by the user or created programmatically, as happens when a RAS connection is made.
            /// </summary>
            ServerCredential = 0x04000,
            /// <summary>
            /// Specifies that the caller will call CredUIConfirmCredentials after checking to determine whether the returned credentials are actually valid. This mechanism ensures that credentials that are not valid are not saved to the credential manager. Specify this flag in all cases unless CREDUI_FLAGS_DO_NOT_PERSIST is specified.
            /// </summary>
            ExpectConfirmation = 0x20000,
            /// <summary>
            /// Consider the credentials entered by the user to be generic credentials.
            /// </summary>
            GenericCredentials = 0x40000,
            /// <summary>
            /// Credential has a username as the target.
            /// </summary>
            UserNameTargetCredentials = 0x80000,
            /// <summary>
            /// Don't allow the user to change the supplied username.
            /// </summary>
            KeepUserName = 0x100000
        }

        #endregion
    }
}
