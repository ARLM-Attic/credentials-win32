using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security;

namespace Evb.Security.Credentials
{
    [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
    internal static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CREDUI_INFO
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }

        [DllImport("CredUI.dll", CharSet = CharSet.Unicode, EntryPoint = "CredUIConfirmCredentialsW", ExactSpelling = true, SetLastError = false)]
        public static extern CredUIReturnCodes CredUIConfirmCredentials(
            string targetName,
            [MarshalAs(UnmanagedType.Bool)] bool confirm);

        [DllImport("CredUI.dll", CharSet = CharSet.Unicode, EntryPoint = "CredUIPromptForCredentialsW", ExactSpelling = true, SetLastError = false)]
        public static extern CredUIReturnCodes CredUIPromptForCredentials(
            ref CREDUI_INFO creditUR,
            string targetName,
            IntPtr reserved,
            int iError,
            StringBuilder userName,
            int maxUserName,
            HandleRef password,
            int maxPassword,
            [MarshalAs(UnmanagedType.Bool)] ref bool pfSave,
            CredentialPromptDialog.CredUIFlags flags);

        internal enum CredUIReturnCodes
        {
            NO_ERROR = 0,
            ERROR_CANCELLED = 1223,
            ERROR_NO_SUCH_LOGON_SESSION = 1312,
            ERROR_NOT_FOUND = 1168,
            ERROR_INVALID_ACCOUNT_NAME = 1315,
            ERROR_INSUFFICIENT_BUFFER = 122,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_INVALID_FLAGS = 1004,
        }
    }
}
